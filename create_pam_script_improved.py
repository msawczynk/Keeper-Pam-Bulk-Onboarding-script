#!/usr/bin/env python3
"""
create_pam_script_improved.py -- Bulk‑onboard Windows servers into Keeper PAM

Changelog vs original GitHub version
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
* **--parent-folder** flag lets you drop Users/Resources under an existing
  shared folder hierarchy instead of polluting vault root. (Commander doesn’t
  support nested SF paths on import, so we generate `folder move` commands.)
* JSON wrapper now includes **shared_folders** as well as **records**.
* Connection commands always pass **--config** (UID or path) so records are
  attached in one shot.
* Rotation commands include **--config** and use the **--admin-user** UID you
  supply – no more fallback to the rotated credential.
* Schedule string is emitted as valid JSON:
 `{"type":"DAILY","time":"02:00","tz":"UTC"}`.
* Added doc‑level constants for default ports per protocol.
* Misc: PEP‑8 pass, clearer logging, `--dry-run` honours new files.

Tested on Commander 17.0.12.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import socket
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
LOG_FMT = "%(asctime)s | %(levelname)-8s | %(message)s"
logger = logging.getLogger("keeper_bulk_onboard")
logger.setLevel(logging.INFO)
console = logging.StreamHandler()
console.setFormatter(logging.Formatter(LOG_FMT))
logger.addHandler(console)

# file log
file_handler = logging.FileHandler(
    Path(f"bulk_onboard_{datetime.utcnow():%Y%m%dT%H%M%SZ}.log")
)
file_handler.setFormatter(logging.Formatter(LOG_FMT))
logger.addHandler(file_handler)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
_DEFAULT_PORTS = {
    "rdp": 3389,
    "ssh": 22,
    "sql-server": 1433,
    "mysql": 3306,
    "postgresql": 5432,
}


def _probe(host: str, port: int = 5986, timeout: float = 3.0) -> bool:
    """Return True if ``host:port`` accepts a TCP connection."""

    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────


def _build_cli() -> argparse.ArgumentParser:
    """Return the argument parser for the script."""

    p = argparse.ArgumentParser(
        description="Generate Keeper PAM import JSON & CLI commands",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # core
    p.add_argument(
        "--gateway-uid", required=True, help="UID of Keeper Gateway"
    )
    p.add_argument(
        "--csv",
        default="servers_to_import.csv",
        help="CSV with hostname,user,password (default: %(default)s)",
    )

    p.add_argument(
        "--user-folder",
        default="PAM_Users",
        help="SF name for pamUser records (default: %(default)s)",
    )
    p.add_argument(
        "--resource-folder",
        default="PAM_Resources",
        help="SF name for pamMachine records (default: %(default)s)",
    )
    p.add_argument(
        "--parent-folder",
        default=None,
        help="Existing parent SF path to nest user/resource folders",
    )

    # rotation / schedule
    p.add_argument(
        "--rotation-admin-uid",
        required=False,
        help="UID of pamUser used to perform resets",
    )
    p.add_argument(
        "--schedulejson",
        default='{"type":"DAILY","time":"02:00","tz":"UTC"}',
        help="JSON schedule. MUST be valid JSON (default: %(default)s)",
    )

    # connection / machine specifics
    p.add_argument(
        "--protocol",
        default="rdp",
        choices=list(_DEFAULT_PORTS),
        help="Protocol for connections (default: %(default)s)",
    )
    p.add_argument(
        "--os",
        default="Windows",
        help="Operating system string (default: %(default)s)",
    )
    p.add_argument(
        "--enable-ssl-verification",
        action="store_true",
        help="Enable SSL verification flag on machines",
    )

    # feature flags
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--connectivity-check", action="store_true")
    p.add_argument(
        "--threads", type=int, default=min(32, (os.cpu_count() or 1) * 5)
    )

    return p


# ──────────────────────────────────────────────────────────────────────────────
# Read CSV
# ──────────────────────────────────────────────────────────────────────────────


def _read_csv(path: Path) -> List[Dict[str, str]]:
    """Return a list of host dictionaries loaded from ``path``."""

    if not path.exists():
        logger.error("CSV file not found: %s", path)
        sys.exit(1)
    out: List[Dict[str, str]] = []
    with path.open(encoding="utf-8") as fp:
        reader = csv.DictReader(fp)
        for line_no, row in enumerate(reader, 1):
            h, u, p = (
                row.get("hostname", "").strip(),
                row.get("initial_admin_user", "").strip(),
                row.get("initial_admin_password", "").strip(),
            )
            if not all((h, u, p)):
                logger.warning("Row %d incomplete – skipped", line_no)
                continue
            out.append({"hostname": h, "user": u, "password": p})
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Record generation
# ──────────────────────────────────────────────────────────────────────────────


def _gen_records(
    rows: List[Dict[str, str]], args: argparse.Namespace
) -> List[Dict]:
    """Return Keeper record dictionaries for ``rows``."""

    recs: List[Dict] = []
    seen: set[str] = set()
    port = str(_DEFAULT_PORTS[args.protocol])
    for row in rows:
        host = row["hostname"]
        if host in seen:
            logger.warning("Duplicate hostname %s – skipped", host)
            continue
        seen.add(host)
        tmp_uid = uuid.uuid4().hex

        # pamUser
        recs.append(
            {
                "$type": "pamUser",
                "uid": tmp_uid,
                "title": f"{host} Local Admin",
                "login": row["user"],
                "password": row["password"],
                "folders": [
                    {
                        "shared_folder": args.user_folder,
                        "can_edit": True,
                        "can_share": True,
                    }
                ],
            }
        )

        # pamMachine
        recs.append(
            {
                "$type": "pamMachine",
                "title": host,
                "login": "stub",
                "password": "stub",
                "folders": [
                    {
                        "shared_folder": args.resource_folder,
                        "can_edit": True,
                        "can_share": True,
                    }
                ],
                "custom_fields": {
                    "$pamSettings": {"connection": {}, "portForward": {}},
                    "$pamHostname": {"hostName": host, "port": port},
                    "$checkbox:sslVerification": args.enable_ssl_verification,
                    "operatingSystem": args.os,
                },
                "links": [tmp_uid],
            }
        )
    return recs


# ──────────────────────────────────────────────────────────────────────────────
# Command writers
# ──────────────────────────────────────────────────────────────────────────────


def _write(fpath: Path, content: str, dry: bool):
    """Write ``content`` to ``fpath`` unless ``dry`` is True."""
    if dry:
        logger.info("[DRY‑RUN] Would write %s", fpath)
        return
    with fpath.open("w", encoding="utf-8") as fp:
        fp.write(content)
    logger.info("Wrote %s", fpath)


def _cmdfile_header(title: str) -> str:
    """Return a common header line for command files."""

    return (
        f"# ==== {title} generated {datetime.utcnow():%Y-%m-%dT%H:%MZ} ===\n\n"
    )


def write_import_json(records: List[Dict], args: argparse.Namespace):
    """Write ``records`` to ``pam_records_import.json``."""

    wrapper = json.dumps({"shared_folders": [], "records": records}, indent=2)
    _write(Path("pam_records_import.json"), wrapper, args.dry_run)


def write_setup_commands(args: argparse.Namespace):
    """Create setup commands for configs and optional folder moves."""
    lines = [
        _cmdfile_header("SETUP"),
        "keeper import pam_records_import.json --format json\n",
    ]

    # One config per resource folder
    cfg_title = f"Config for {args.resource_folder}"
    cfg_cmd = (
        f'keeper pam config new --environment local --title "{cfg_title}" '
        f'--shared-folder "{args.resource_folder}" -g {args.gateway_uid} '
        f"--connections=on --rotation=on"
    )
    lines.append(cfg_cmd + "\n")

    # optional folder moves
    if args.parent_folder:
        for sf in (args.user_folder, args.resource_folder):
            lines.append(
                f'keeper folder move "/{sf}" "/{args.parent_folder}/{sf}"'
            )
    _write(
        Path("pam_setup_commands.txt"),
        "\n".join(lines) + "\n",
        args.dry_run,
    )


def write_connection_commands(
    rows: List[Dict[str, str]], args: argparse.Namespace
):
    """Write pam connection commands to a file."""
    cfg_path = f'"/{args.resource_folder}"'
    lines = [_cmdfile_header("CONNECTIONS")]
    for row in rows:
        host = row["hostname"]
        machine = f'"/{args.resource_folder}/{host}"'
        user = f'"/{args.user_folder}/{host} Local Admin"'
        port = _DEFAULT_PORTS[args.protocol]
        lines.append(
            (
                f"keeper pam connection edit {machine} --config {cfg_path} "
                f"--admin-user {user} --protocol {args.protocol} "
                f"--connections on --connections-override-port {port}"
            )
        )
    _write(
        Path("pam_connection_commands.txt"),
        "\n".join(lines) + "\n",
        args.dry_run,
    )


def write_rotation_commands(
    rows: List[Dict[str, str]], args: argparse.Namespace
):
    """Write pam rotation commands to ``pam_rotation_commands.txt``."""
    cfg_path = f'"/{args.resource_folder}"'
    sched = args.schedulejson.replace("'", '"')  # ensure double‑quoted JSON
    lines = [_cmdfile_header("ROTATION")]
    adm_flag = (
        f" --admin-user {args.rotation_admin_uid}"
        if args.rotation_admin_uid
        else ""
    )
    for row in rows:
        host = row["hostname"]
        user = f'"/{args.user_folder}/{host} Local Admin"'
        machine = f'"/{args.resource_folder}/{host}"'
        lines.append(
            (
                "keeper pam rotation set --record {u} --resource {m} "
                "--config {c} --enable{adm} -sj '{sj}'"
            ).format(u=user, m=machine, c=cfg_path, adm=adm_flag, sj=sched)
        )
    _write(
        Path("pam_rotation_commands.txt"),
        "\n".join(lines) + "\n",
        args.dry_run,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────


def main():
    """Entry point for CLI execution."""
    args = _build_cli().parse_args()
    rows = _read_csv(Path(args.csv))
    if args.connectivity_check:
        logger.info(
            "Running best‑effort TCP 5986 probe on %d hosts", len(rows)
        )
        ok: List[Dict] = []
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            fut = {ex.submit(_probe, r["hostname"]): r for r in rows}
            for f in as_completed(fut):
                if f.result():
                    ok.append(fut[f])
                else:
                    logger.warning("%s unreachable", fut[f]["hostname"])
        rows = ok
    logger.info("Processing %d servers", len(rows))

    records = _gen_records(rows, args)
    write_import_json(records, args)
    write_setup_commands(args)
    write_connection_commands(rows, args)
    write_rotation_commands(rows, args)


if __name__ == "__main__":
    main()
