import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import json  # noqa: E402
from types import SimpleNamespace  # noqa: E402
import create_pam_script_improved as script  # noqa: E402


def test_write_import_json(monkeypatch, tmp_path):
    captured = {}

    def fake_write(path, content, dry):
        captured["path"] = Path(path)
        captured["content"] = content
        captured["dry"] = dry

    monkeypatch.setattr(script, "_write", fake_write)
    records = [{"uid": "1"}]
    args = SimpleNamespace(dry_run=False)
    script.write_import_json(records, args)
    data = json.loads(captured["content"])
    assert data["records"] == records
    assert captured["path"].name == "pam_records_import.json"


def test_rotation_command_format(monkeypatch):
    captured = {}

    def fake_write(path, content, dry):
        captured["content"] = content

    monkeypatch.setattr(script, "_write", fake_write)
    monkeypatch.setattr(script, "_cmdfile_header", lambda t: "HEADER\n")
    rows = [{"hostname": "srv1"}]
    args = SimpleNamespace(
        user_folder="Users",
        resource_folder="Resources",
        schedulejson="{}",
        rotation_admin_uid=None,
        dry_run=False,
        protocol="rdp",
    )
    script.write_rotation_commands(rows, args)
    assert (
        captured["content"]
        .strip()
        .splitlines()[-1]
        .endswith(f"-sj '{args.schedulejson}'")
    )
    # ensure no double spaces
    assert "  -sj" not in captured["content"]
