# Keeper PAM Bulk Onboarding Script

Automate the onboarding of servers and credentials into [Keeper Secrets Manager (KSM)](https://keepersecurity.com/secrets-manager.html) for PAM. This script converts a simple CSV into fully configured, rotation-enabled PAM records, with a structured folder hierarchy and zero-touch setup.

---

## Features

* **CSV-Driven**: Single CSV input (`hostname,username,password`)
* **Hierarchical Structure**: Automatically organizes records under `/PAM Environments/<Project>/<Resources|Users>`
* **End-to-End Automation**: Optional flags to control folder creation, gateway bootstrapping, PAM config, and more
* **Idempotent**: Folder creation scripts are safe to re-run—no accidental overwrites
* **Opinionated Defaults**: Ports, schedules, and naming conventions follow best practice (customizable)
* **Offline Generation**: No API calls during script run; everything generated for review and approval
* **Detailed Logging**: Timestamped log for each run

---

## Prerequisites

* **Python 3**
* **[Keeper Commander](https://docs.keeper.io/secrets-manager/secrets-manager/keeper-commander/command-line-interface)** (installed and configured)

---

## Installation

Save the script as `create_pam_script_improved.py`
Make it executable:

```bash
chmod +x create_pam_script_improved.py
```

---

## CSV Format

No header. Three columns:

```
hostname,username,password
```

Example:

```
web-server-01,admin,P@ssw0rdABCD
db-server-01,sa,Another$ecret1234
linux-host-prod,root,SshKeyP@ss!
```

---

## Arguments

| Argument              | Required | Description                                                   |
| --------------------- | -------- | ------------------------------------------------------------- |
| `--csv`               | Yes      | Path to input CSV                                             |
| `--project-name`      | No       | Project name (folders/gateway/config). Default: `PAM Project` |
| `--create-folders`    | No       | Generate folder structure                                     |
| `--create-gateway`    | No       | Generate new KSM Gateway commands                             |
| `--create-pam-config` | No       | Generate new PAM Config commands                              |
| `--gateway-uid`       | Maybe    | Existing Gateway UID (required if not creating new gateway)   |
| `--protocol`          | No       | Connection protocol (`WINRM`, `SSH`). Default: `WINRM`        |
| `--port`              | No       | Override protocol default port                                |
| `--enable-recording`  | No       | Enable session recording                                      |
| `--schedulejson`      | No       | Password rotation schedule in JSON (default: daily 02:00 UTC) |
| `--dry-run`           | No       | Generate scripts but do not print execution instructions      |
| `--user-folder`       | No       | Override default users folder name                            |
| `--resource-folder`   | No       | Override default resources folder name                        |

---

## Example: Full Automation (New Project)

```bash
./create_pam_script_improved.py \
  --csv finance_servers.csv \
  --project-name "Finance Prod" \
  --create-folders \
  --create-gateway \
  --create-pam-config \
  --protocol WINRM \
  --enable-recording
```

**Execution:**

1. Run the command above.
2. Run setup script:

   ```bash
   bash pam_setup_commands_[timestamp].txt
   ```
3. Enroll the Gateway using the provided one-time token, then set:

   ```bash
   export GATEWAY_UID=$(pam gateway list --format json | jq -r '.[] | select(.name=="Finance Prod Gateway") | .uid')
   export PAM_CONFIG_UID=$(pam config list --format json | jq -r '.[] | select(.title=="Finance Prod Configuration") | .uid')
   ```
4. Run connection, rotation, and cleanup scripts:

   ```bash
   bash pam_connection_commands_[timestamp].txt
   bash pam_rotation_commands_[timestamp].txt
   bash pam_cleanup_commands_[timestamp].txt
   ```

---

## Example: Add Servers to Existing Project

1. Get existing UIDs:

   ```bash
   pam gateway list
   pam config list
   ```
2. Run:

   ```bash
   ./create_pam_script_improved.py \
     --csv new_staging_servers.csv \
     --project-name "Staging" \
     --gateway-uid "YourGatewayUID" \
     --protocol SSH
   ```
3. Set:

   ```bash
   export PAM_CONFIG_UID="YourPamConfigUID"
   ```
4. Run the generated import/connection scripts.

---

## Logging

Each run generates a timestamped log:
`pam_onboard_log_[timestamp].txt`

---

## Pro Tips & Warnings

* **Always validate your CSV**—bad or duplicate records will cause issues.
* **Review all generated scripts before running** (especially in production).
* **Folder creation scripts are safe to rerun**—useful for incremental onboarding.
* **Handle CSVs with care**—they contain live credentials.

---

## Contributions

Open PRs/issues for bugs, feature requests, or improvements.
