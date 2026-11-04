# Upload templates

Uploads are **optional**. The Quick Check works from the questionnaire alone. Uploads let the Full Assessment check every account and device instead of relying on memory.

| Template | What it describes | Feeds module | Guide | Worked example |
|---|---|---|---|---|
| `users_permissions.csv` | Every login: admin or not, MFA, last sign-in | 1 Identity | [guide](guides/users_permissions.md) | [example](examples/users_permissions_example.csv) |
| `firewall_rules.csv` | Router/firewall allow and deny rules | 2 Network | [guide](guides/firewall_rules.md) | [example](examples/firewall_rules_example.csv) |
| `patch_inventory.csv` | Devices, OS version, updates, key software | 3 Patching | [guide](guides/patch_inventory.md) | [example](examples/patch_inventory_example.csv) |
| `endpoint_protection.csv` | Antivirus, encryption, screen lock per device | 4 Endpoint | [guide](guides/endpoint_protection.md) | [example](examples/endpoint_protection_example.csv) |
| `backup_jobs.csv` | Each backup: where it goes, last success, last test | 5 Recovery | [guide](guides/backup_jobs.md) | [example](examples/backup_jobs_example.csv) |

## Rules every template follows

* First row is the header, exactly as shown. Column order does not matter; names do.
* CSV (UTF-8) or Excel `.xlsx` (first sheet is read).
* Dates are `YYYY-MM-DD`. Leave a cell empty if you do not know.
* Yes/No columns use `Y` or `N`. Columns that allow it also accept `unknown`.
* **Replace real names before you upload.** Use labels like `owner`, `cashier-1`, `office-pc`. The app also hashes user IDs, shortens IP addresses to their network, and turns device names into role labels the moment a file is read, and nothing is saved on the server. Still, the safest data is data you never upload.

## Export scripts (Windows / Microsoft 365)

For businesses with a Windows PC or Active Directory, `export_scripts/` has read-only PowerShell scripts that write the template format directly, already using labels instead of names:

| Script | Produces | Needs |
|---|---|---|
| `Export-NSLocalDevice.ps1` | One row each for `patch_inventory.csv` and `endpoint_protection.csv` for the computer it runs on | Windows 10/11, run as administrator for BitLocker status |
| `Export-NSADUsers.ps1` | `users_permissions.csv` from Active Directory | RSAT ActiveDirectory module, domain read access |

The scripts only **read** settings. They never change anything. Run them only on computers you own or are authorized to assess.

## What each column is checked against

The column types and allowed values are enforced by `engine/schemas.py` (Pydantic). If an upload does not match, the owner sees a plain message such as: *"Column last_login_date is missing. Here is the template."*
