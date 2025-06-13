# Guide: Bulk Onboarding Servers for Automated Password Rotation in Keeper

**Objective:** This guide details a fully automated process for bulk-creating Keeper PAM records for a large number of Windows servers, creating unique credentials and connections for each, linking them to the correct PAM configuration, and enabling automated password rotation.

---

## Security Warning

<div style="border: 2px solid #FBCBBA; border-radius: 8px; padding: 16px; background-color: #FEF3F2; color: #B42318;">
    <strong>CRITICAL:</strong> The source <code>.csv</code> file and the generated <code>pam_records_import.json</code> file will contain plaintext credentials. These files must only be created and used on a trusted, encrypted administrative workstation. After the import is complete and verified, use the script's <code>--cleanup</code> option or manually perform a secure deletion of these files.
</div>

---

## Workflow Overview

The process uses a professional-grade Python script to automate the generation of configuration files, which are then used with Keeper Commander to perform the bulk operations safely and efficiently.

1.  **Prepare Data:** A CSV file is created listing all target servers and their current, shared local administrator credentials.
2.  **Generate Configurations:** The Python script is run from the command line. It reads the CSV and generates:
    * A `JSON` file containing the definitions for all the new `pamUser` and `pamMachine` records.
    * A single, executable `TXT` file containing the entire sequence of Keeper Commander commands.
3.  **Execute in Keeper Commander:** The generated text file is executed with a single command (`run "..."`) to perform all steps in sequence.

---

## Prerequisites

* **Keeper Commander:** You must have a recent version (v17.0.11+) installed and configured on your machine.
* **Keeper Gateway:** A Keeper Gateway must be deployed with network access to the target Windows servers on **TCP port 5986** (the default for WinRM over HTTPS). You will need the **UID** of this gateway.
* **Rotation Administrator (Recommended):** You should have an existing `pamUser` record in Keeper containing the credentials of a privileged account (e.g., a domain admin or service account) that has permission to reset passwords on all target servers. You will need the **UID** of this record.
* **WinRM Certificate Trust:** The Keeper Gateway must trust the Certificate Authority (CA) that issued the WinRM TLS certificates on your target servers. If rotations fail due to certificate errors, re-run the script *without* the `--enable-ssl-verification` flag for testing purposes. For production, the recommended solution is to import the CA into the gateway's trust store.
* **Python:** Python 3.6+ must be installed to run the script.
* **WinRM Enabled on Servers:** WinRM over HTTPS must be enabled on all target servers.

---

## Step 1: Prepare the CSV Data File

Create a CSV file named `servers_to_import.csv`. It must contain the following three columns:

* `hostname`: The IP address or fully qualified domain name (FQDN) of the Windows server.
* `initial_admin_user`: The username of the current, shared local administrator account.
* `initial_admin_password`: The current password for the shared local administrator account.

#### Example: `servers_to_import.csv`

```csv
hostname,initial_admin_user,initial_admin_password
10.20.30.101,local-admin,CurrentSharedPassword123!
10.20.30.102,local-admin,CurrentSharedPassword123!
win-server-201.corp.local,local-admin,CurrentSharedPassword123!
```

Save this file in a new, dedicated folder for this task.

---

## Step 2: Save the Improved Python Script

Save the following Python code into a file named `create_pam_script_improved.py` within the same folder as your CSV file.

#### The Script: `create_pam_script_improved.py`

```python
#!/usr/bin/env python3
"""
create_pam_script_improved.py -- Bulk-onboard Windows servers into Keeper PAM

This version incorporates expert feedback for production use:
* **Argparse CLI** – Gateway UID, folder names, input/output paths, and feature flags
* **Separate Folders** - Creates pamUser and pamMachine records in different shared folders.
* **Hard Blocker Fixes** - Uses "$type" in JSON and corrected command syntax (`pam rotation edit`).
* **Correct JSON Schema** - Includes a blank "$pamSettings" field and dummy credentials to prevent command failures.
* **Rotation Admin UID** - Allows specifying a central admin account for all rotations
* **Executable Script Output** - Generates a single .txt file with separate commands (no run-batch).
* **Explicit Connection Editing** - Generates a specific `pam connection edit` command for each resource with recording and port override.
* **Force Flag** - Includes --force on rotation commands to enable full automation.
* **Structured logging** – INFO/WARNING/ERROR levels to console and to a timestamped log file
* **UUID-based temp UIDs** – Avoid collisions on short hostnames
* **Idempotency** – Skip duplicate hostnames and warn the operator
* **Connectivity probe (optional)** – Parallel TCP check to port 5986 before generating JSON
* **Dry-run mode** – Preview records/commands without writing anything
* **Cleanup option** – Securely delete the CSV & generated artefacts after successful run
"""

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
from typing import List, Dict

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"
logger = logging.getLogger("keeper_bulk_onboard")
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(console_handler)

log_file = Path(f"bulk_onboard_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.log")
file_handler = logging.FileHandler(log_file)
file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(file_handler)

# ---------------------------------------------------------------------------
# CLI arguments
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate Keeper PAM import JSON & command set for Windows servers.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Core arguments
    parser.add_argument("--gateway-uid", required=True, help="UID of the Keeper Gateway that will manage these records.")
    parser.add_argument("--user-folder", default="PAM Users", help="Shared folder for the created pamUser records (default: %(default)s)")
    parser.add_argument("--resource-folder", default="PAM Resources", help="Shared folder for the created pamMachine records (default: %(default)s)")
    parser.add_argument("--csv", default="servers_to_import.csv", help="Input CSV containing hostname,initial_admin_user,initial_admin_password (default: %(default)s)")
    
    # Rotation-specific arguments
    parser.add_argument("--rotation-admin-uid", help="UID of an existing PAM User record to use as the administrator for all password rotations. If not provided, the credential being rotated is used.")
    parser.add_argument("--schedulejson", "-sj", help="JSON string to define a rotation schedule. Example for daily at 2AM:\n\'{\"type\":\"DAILY\", \"time\":\"02:00\", \"tz\":\"UTC\"}\'")

    # Record & Connection details
    parser.add_argument("--protocol", default="rdp", choices=["rdp", "ssh", "vnc", "telnet", "sql-server", "mysql", "postgresql", "kubernetes"], help="The connection protocol to configure for the machine records (default: %(default)s).")
    parser.add_argument("--connection-port", type=int, default=3389, help="Override port for the connection (e.g., 3389 for RDP). (default: %(default)s)")
    parser.add_argument("--os", default="Windows", help="Operating system to set on pamMachine records (default: %(default)s)")
    parser.add_argument("--enable-ssl-verification", action="store_true", help="Enable the 'SSL Verification' checkbox on machine records. Recommended for production.")
    parser.add_argument("--enable-recording", action="store_true", help="Enable graphical and text-based session recording on the connections.")

    # File path arguments
    parser.add_argument("--json-out", default="pam_records_import.json", help="Output JSON file path (default: %(default)s)")
    parser.add_argument("--cmd-out", default="onboarding_script.txt", help="Output executable command file (default: %(default)s)")
    
    # Feature flags
    parser.add_argument("--dry-run", action="store_true", help="Do not write any files, just log what would happen.")
    parser.add_argument("--skip-pam-config", action="store_true", help="Skip the 'pam config new' command. Use if the folders are already linked to a PAM config.")
    parser.add_argument("--connectivity-check", action="store_true", help="Best-effort TCP probe to each host on port 5986 before generating records. Does not guarantee WinRM will succeed.")
    parser.add_argument("--cleanup", action="store_true", help="Secure-delete the CSV and generated artefacts after successful run (use with caution).")
    parser.add_argument("--threads", type=int, default=min(32, (os.cpu_count() or 1) * 5), help="Thread count for connectivity checks (default: %(default)s)")

    return parser.parse_args()

# ---------------------------------------------------------------------------
# Core Logic
# ---------------------------------------------------------------------------

def probe_host(host: str, port: int = 5986, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False

def connectivity_scan(hosts: List[str], threads: int) -> List[str]:
    reachable = []
    logger.info("Starting best-effort connectivity probe to TCP 5986 on %d hosts", len(hosts))
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_host = {executor.submit(probe_host, h): h for h in hosts}
        for future in as_completed(future_to_host):
            host = future_to_host[future]
            if future.result():
                reachable.append(host)
            else:
                logger.warning("Host %s is unreachable on 5986 – skipping", host)
    return reachable

def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        logger.error("CSV file not found: %s", path)
        sys.exit(1)
    servers = []
    with path.open(newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for idx, row in enumerate(reader, start=1):
            hostname = row.get("hostname", "").strip()
            user = row.get("initial_admin_user", "").strip()
            password = row.get("initial_admin_password", "").strip()
            if not all([hostname, user, password]):
                row['initial_admin_password'] = '********' # Mask password in logs
                logger.warning("Row %d missing data, skipping: %s", idx, row)
                continue
            servers.append({"hostname": hostname, "user": user, "password": password})
    return servers

def generate_records(servers: List[Dict[str, str]], args: argparse.Namespace) -> List[Dict]:
    records = []
    seen_hosts = set()
    for s in servers:
        host = s["hostname"]
        if host in seen_hosts:
            logger.warning("Duplicate hostname %s in CSV – ignoring subsequent entry", host)
            continue
        seen_hosts.add(host)
        temp_uid = uuid.uuid4().hex
        
        pam_user_record = {
            "$type": "pamUser", "uid": temp_uid, "title": f"{host} Local Admin",
            "login": s["user"], "password": s["password"],
            "folders": [{"shared_folder": args.user_folder, "can_edit": True, "can_share": True}],
        }
        
        pam_settings = {"connection": {}, "portForward": {}}
        
        custom_fields = {
            "$pamHostname": {"hostName": host, "port": "5986"},
            "$pamSettings": pam_settings,
            "operatingSystem": args.os,
            "$checkbox:sslVerification": args.enable_ssl_verification,
        }
        
        pam_machine_record = {
            "$type": "pamMachine", "title": host,
            "login": "dummy", "password": "dummy",
            "folders": [{"shared_folder": args.resource_folder, "can_edit": True, "can_share": True}],
            "custom_fields": custom_fields,
            "links": [temp_uid],
        }
        records.extend([pam_user_record, pam_machine_record])
    return records

def write_json(records: List[Dict], out_path: Path, dry_run: bool):
    if dry_run:
        logger.info("[DRY-RUN] Would write JSON with %d records to %s", len(records), out_path)
        return
    with out_path.open("w", encoding="utf-8") as fp:
        json.dump({"shared_folders": [], "records": records}, fp, indent=2)
    logger.info("Wrote JSON import file: %s", out_path)

def write_executable_script(servers: List[Dict[str, str]], args: argparse.Namespace):
    """Generates a single, consolidated script for use with `run`."""
    commands = []
    
    # Step 1: Import
    commands.append(f"# Step 1: Import all User and Machine records")
    commands.append(f"import {args.json_out} --format json")

    # Step 2: Configure Folders
    config_path = f'/"{args.resource_folder}/Config for {args.resource_folder}"'
    commands.append(f"\n# Step 2: Create PAM Configurations to link folders to the Gateway")
    if not args.skip_pam_config:
        commands.append(f'pam config new --environment local --title "Config for {args.user_folder}" --shared-folder "{args.user_folder}" -g {args.gateway_uid} --connections=on --rotation=on')
        commands.append(f'pam config new --environment local --title "Config for {args.resource_folder}" --shared-folder "{args.resource_folder}" -g {args.gateway_uid} --connections=on --rotation=on')
    
    # Step 3: Enable Recording on the Configuration itself
    if args.enable_recording:
        commands.append(f'\n# Step 3: Enable Session Recording on the Resource Configuration')
        commands.append(f'pam connection edit {config_path} --connections-recording=on --typescript-recording=on')

    # Step 4: Explicitly edit and enable the connection for each resource
    commands.append("\n# Step 4: Enable Connections and link Admin User for each new resource")
    recording_flags = ""
    if args.enable_recording:
        recording_flags = "--connections-recording on --typescript-recording on"

    for s in servers:
        machine_path = f'/"{args.resource_folder}"/"{s["hostname"]}"'
        user_path = f'/"{args.user_folder}"/"{s["hostname"]} Local Admin"'
        connection_parts = [
            'pam connection edit',
            machine_path,
            f'--config {config_path}',
            f'--protocol {args.protocol}',
            f'--admin-user {user_path}',
            '--connections on',
            f'--connections-override-port {args.connection_port}',
            recording_flags
        ]
        commands.append(' '.join(filter(None, connection_parts)))
    
    # Step 5: Set Rotation Policy
    commands.append("\n# Step 5: Set Rotation Policy for all new credentials")
    rotation_admin_arg = f'--admin-user "{args.rotation_admin_uid}"' if args.rotation_admin_uid else ""
    schedule_arg = f'-sj \'{args.schedulejson}\'' if args.schedulejson else ""
    
    for s in servers:
        user_path = f'/"{args.user_folder}"/"{s["hostname"]} Local Admin"'
        machine_path = f'/"{args.resource_folder}"/"{s["hostname"]}"'
        rotation_parts = [
            'pam rotation edit',
            f'--record {user_path}',
            f'--resource {machine_path}',
            '--enable',
            '--force', # Add force flag to avoid interactive prompts
            rotation_admin_arg,
            schedule_arg
        ]
        commands.append(' '.join(filter(None, rotation_parts)))

    out_path = Path(args.cmd_out)
    title = "KEEPER COMMANDER ONBOARDING SCRIPT"
    header = [f"# --- {title} ---", f"# Generated {datetime.utcnow().isoformat()}Z\n"]
    content = "\n".join(header + commands)

    if args.dry_run:
        logger.info("[DRY-RUN] Would write executable script to %s:\n%s", out_path, content)
        return
    with out_path.open("w", encoding="utf-8") as fp:
        fp.write(content)
    logger.info("Wrote executable command file: %s", out_path)

def shred_file(path: Path):
    if not path.exists(): return
    try:
        size = path.stat().st_size
        with path.open("ba", buffering=0) as f:
            f.seek(0); f.write(os.urandom(size)); f.flush(); os.fsync(f.fileno())
        path.unlink()
        logger.info("Best-effort secure delete of %s", path)
    except Exception as exc:
        logger.error("Failed to shred %s: %s", path, exc)

# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    logger.info("Starting bulk onboarding script…")
    logger.warning("The CSV contains plaintext credentials. Ensure it is kept on an encrypted volume and deleted after use!")

    servers = read_csv(Path(args.csv))
    logger.info("Loaded %d server entries from %s", len(servers), args.csv)

    if args.connectivity_check:
        hosts = [s["hostname"] for s in servers]
        reachable = connectivity_scan(hosts, args.threads)
        servers = [s for s in servers if s["hostname"] in reachable]
        logger.info("%d hosts are reachable and will be processed after probe", len(servers))
        if not servers:
            logger.error("No reachable hosts – aborting"); sys.exit(1)

    records = generate_records(servers, args)
    logger.info("Generated %d Keeper records (%d servers)", len(records), len(servers))

    write_json(records, Path(args.json_out), args.dry_run)
    write_executable_script(servers, args)
    
    if args.cleanup and not args.dry_run:
        logger.info("Cleanup flag enabled – shredding temporary artefacts…")
        shred_file(Path(args.csv)); shred_file(Path(args.json_out)); shred_file(Path(args.cmd_out))

    logger.info("Done.")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: logger.warning("Interrupted by user."); sys.exit(130)
```

---

## Step 3: Run the Script from the Command Line

1.  **Open a terminal** or command prompt and navigate to the folder containing the script and the CSV file.
2.  **Run the script** with your specific Gateway UID and other desired options.

    ```bash
    # Recommended execution with recording enabled
    python create_pam_script_improved.py --gateway-uid YOUR_GATEWAY_UID \
      --user-folder "Windows Local Admins" \
      --resource-folder "Windows Servers" \
      --rotation-admin-uid YOUR_ADMIN_USER_UID \
      -sj '{"type":"DAILY", "time":"02:00", "tz":"UTC"}' \
      --enable-recording
    ```

### Useful Command-Line Options

* **`--user-folder <name>`**: Name of the shared folder for `pamUser` records.
* **`--resource-folder <name>`**: Name of the shared folder for `pamMachine` records.
* **`--rotation-admin-uid <UID>`**: UID of the existing `pamUser` record that will perform the password rotations.
* **`-sj <JSON>`** or **`--schedulejson <JSON>`**: A JSON string to define the rotation schedule.
* **`--os <OS>`**: Set the operating system on machine records (default: "Windows").
* **`--enable-ssl-verification`**: Enables the SSL verification checkbox on records.
* **`--enable-recording`**: **(New)** Enables graphical and text-based session recording on connections.
* **`--connection-port <port>`**: **(New)** Set the port for the connection (e.g., 3389 for RDP).
* **`--skip-pam-config`**: Use this if the Shared Folders are already linked to a PAM configuration.
* **`--dry-run`**: Perform a test run without creating or changing any files.
* **`--connectivity-check`**: Best-effort test of connectivity to servers before generating files.
* **`--cleanup`**: Securely delete the sensitive CSV and generated scripts after a successful run.

---

## Step 4: Execute the Generated Commands

The workflow is now a fully automated, two-step process.

1.  **Navigate to your working directory:** In your terminal, `cd` into the directory where your script and CSV file are located. This is crucial for the `import` command to find the JSON file.

    ```bash
    cd "C:\Scripts\Bulk import"
    ```

2.  **Start Keeper Commander Shell:**

    ```bash
    keeper shell
    ```

3.  **Run the Generated Script:** Execute the single command file generated by the Python script.

    ```bash
    run "onboarding_script.txt"
    ```

This will execute all commands in sequence, from importing records to setting rotation policies, without any manual intervention required. After the script finishes, you can manually verify the records in the Web Vault.
