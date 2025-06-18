# Keeper PAM Bulk Onboarding Script

> **Status:** ✅ **Maintained** – tested on **Keeper Commander ≥ 17.0.12**
>
> Automates large‑scale creation of **pamUser** / **pamMachine** records, PAM Configs, Connections and Rotation schedules for Windows (or any WinRM‑enabled) servers.
>
> **New in this fork**
>
> | Feature                    | Description                                                                                                                                                       |
> | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
> | **Nested folders**         | `--parent-folder` lets you drop the generated *Users* / *Resources* shared‑folders under an existing hierarchy instead of cluttering the vault root.              |
> | **Always‑valid JSON**      | Output file now wraps records with `{ "shared_folders": [], "records": […] }` and includes the blank `$pamSettings` object Commander expects.                     |
> | **One‑shot attach**        | Connection & Rotation commands now inject `--config`, so records are immediately bound to the right PAM Configuration – no more “resource not associated” errors. |
> | **Proper schedule flag**   | Emits a valid JSON string for `-sj`, fixing the `JSONDecodeError` seen in 17.0.11.                                                                                |
> | **Ports by protocol**      | Auto‑selects the correct default port (RDP 3389, SSH 22, etc.).                                                                                                   |
> | **Cleaner logs / dry‑run** | Every output file respects `--dry-run`; logs go to `bulk_onboard_YYYYMMDDThhmmssZ.log`.                                                                           |
>
> Legacy flags/behaviour remain unchanged – you can drop‑in replace the original script and old automation still works.

---

## TL;DR

```bash
python3 create_pam_script_improved.py \
  --gateway-uid <GW_UID> \
  --csv servers_to_import.csv \
  --user-folder PAM_Users \
  --resource-folder PAM_Resources \
  --parent-folder "My Vault/TestFolder" \
  --rotation-admin-uid <ADMIN_UID>

# import & run
keeper import pam_records_import.json --format json
bash pam_setup_commands.txt
bash pam_connection_commands.txt
bash pam_rotation_commands.txt
```

*Everything* will be wired, enabled and scheduled – zero manual edits.

### Using the custom Commander fork

This project relies on the [pam-import-add-directory-admin-for-local-machines](https://github.com/Keeper-Security/Commander/tree/pam-import-add-directory-admin-for-local-machines) branch of **Keeper Commander**.
Clone the repository and install it with `pip install -e .` before running the
commands below.

### Converting CSV to JSON

Give the script a simple CSV with `hostname,initial_admin_user,initial_admin_password` and it will produce `pam_records_import.json` along with the helper command files.
For example the CSV

```csv
server1,admin,1234
server2,admin,1234
server3,admin,1234
```

becomes a JSON wrapper ready for `keeper import` once you run:

```bash
python3 create_pam_script_improved.py --gateway-uid <GW_UID> --csv servers.csv
```

---

## Prerequisites

| Requirement          | Minimum                                              |
| -------------------- | ---------------------------------------------------- |
| **Keeper Commander** | **17.0.11** (17.0.12 recommended)                    |
| **Keeper Gateway**   | Network path to targets on TCP 5986                  |
| **Python**           | 3.8+                                                 |
| **CSV data**         | `hostname,initial_admin_user,initial_admin_password` |
| **WinRM**            | HTTPS enabled on target servers                      |

---

## CSV format

```csv
hostname,initial_admin_user,initial_admin_password
dc01.example.com,local-admin,CurrentSharedPassword123!
10.20.30.42,local-admin,CurrentSharedPassword123!
```

---

## Command‑line flags (high‑lights)

| Flag                        | Default                                          | Notes                                                     |
| --------------------------- | ------------------------------------------------ | --------------------------------------------------------- |
| `--gateway-uid`             | *required*                                       | UID of the Keeper Gateway managing these servers          |
| `--csv`                     | `servers_to_import.csv`                          |                                                           |
| `--user-folder`             | `PAM_Users`                                      | Shared‑folder for **pamUser** records                     |
| `--resource-folder`         | `PAM_Resources`                                  | Shared‑folder for **pamMachine** records                  |
| `--parent-folder`           | *(none)*                                         | Existing SF path to nest the two generated folders        |
| `--rotation-admin-uid`      | *(none)*                                         | UID of a central admin credential used for resets         |
| `--schedulejson`            | `{ "type":"DAILY", "time":"02:00", "tz":"UTC" }` | Any valid rotation schedule                               |
| `--protocol`                | `rdp`                                            | `ssh`, `sql-server`, `mysql`, `postgresql` also supported |
| `--enable-ssl-verification` | off                                              | Adds the checkbox to each **pamMachine**                  |
| `--dry-run`                 | off                                              | Logs & file previews only – no writes                     |

Run `--help` for the full list.

---

## Generated artefacts

| File | What it contains |
| ------- | ---------------- |
| `pam_records_import.json` | Ready-to-import records (wrapper + blank `$pamSettings`) |
| `pam_setup_commands.txt` | `keeper import` + `pam config new` + optional `folder move` |
| `pam_connection_commands.txt` | One `pam connection edit` per machine (includes `--config`) |
| `pam_rotation_commands.txt` | One `pam rotation set` per credential (includes `--config` & schedule) |
| **Log** | `bulk_onboard_YYYYMMDDThhmmssZ.log` – INFO/WARN/ERROR lines |

---

## Typical workflow

1. **Generate files** – run the script (use `--dry-run` first).
2. **Import** – `keeper import pam_records_import.json --format json`.
3. **Set up configs** – `bash pam_setup_commands.txt`.
4. **Attach connections** – `bash pam_connection_commands.txt`.
5. **Enable rotation** – `bash pam_rotation_commands.txt`.
6. **Validate** –

   ```bash
   pam connection list --folder "/PAM_Resources"
   pam rotation  list --folder "/PAM_Users"
   ```
7. **Run tests** – `pytest`.

---

## FAQ

---

**Q: Can I run the script multiple times?**

Yes. Duplicate hostnames in the CSV are ignored with a warning in the log.

**Q: What happens if a server is unreachable?**

Use `--connectivity-check` to probe TCP 5986. Hosts that fail the check are
skipped so the generated files contain only reachable machines.


