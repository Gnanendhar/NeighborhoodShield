# backup_jobs.csv — backups

**Why:** finds backups that never left the building, that have never been test-restored, that stopped working, that are not encrypted, or that are kept too briefly to survive ransomware (CIS v8.1 11.1–11.4).

| Column | Allowed values | Notes |
|---|---|---|
| job_id | any | |
| source_system | label | what is backed up: `office-pc documents`, `square sales data` |
| destination_type | `same_device` `local_external` `network_share` `cloud` `offline` | `offline` = unplugged drive kept elsewhere |
| schedule | `daily` `weekly` `monthly` `manual` | |
| last_success_date | YYYY-MM-DD | |
| last_restore_test_date | YYYY-MM-DD or empty | empty = never tested |
| encrypted | `Y` `N` `unknown` | |
| retention_days | whole number | how far back you can go |

## How to export

**Veeam Agent / Backup & Replication** — *Home → Last 24 hours / Jobs*, or the job report (HTML/CSV). Docs: https://helpcenter.veeam.com/

**Windows File History** — *Control Panel → File History* shows the last copy date and drive. **OneDrive / Google Drive** — destination `cloud`, schedule `daily`, retention 30 days by default for deleted files (OneDrive "Restore your OneDrive" goes back 30 days).

**Backblaze, Carbonite, iDrive** — the web dashboard shows last backup and retention.

**External drive by hand** — one row: `local_external` (or `offline` if it is unplugged and taken home), `manual`, and the date on the newest folder.
