# patch_inventory.csv — devices, updates, and key software

**Why:** finds operating systems past end-of-life (looked up in a dated snapshot of endoflife.date), devices with critical updates waiting over 30 days, unsupported business software, and software listed in CISA's Known Exploited Vulnerabilities catalog (CIS v8.1 2.1–2.3, 7.1–7.4).

| Column | Allowed values | Notes |
|---|---|---|
| device_id | label | `office-pc`, `owner-laptop` |
| device_type | `desktop` `laptop` `tablet` `phone` `server` `pos_terminal` `router` | |
| os_name | text | `Windows`, `macOS`, `iPadOS`, router maker |
| os_version | text | `10 22H2`, `11 24H2`, `Sonoma 14` (from `winver`) |
| auto_update_enabled | `Y` `N` | |
| last_patch_date | YYYY-MM-DD | |
| pending_critical_updates | whole number | 0 if none |
| key_software_name | text | One important program per row (add rows for more) |
| key_software_version | text | |
| vendor_supported | `Y` `N` `unknown` | Is the maker still fixing it? |

## How to export

**Windows (one PC)** — run `export_scripts/Export-NSLocalDevice.ps1`. It reads the edition and version (`Get-CimInstance Win32_OperatingSystem`, `DisplayVersion`), the latest installed update (`Get-HotFix`), and Windows Update policy. Docs: https://learn.microsoft.com/powershell/module/microsoft.powershell.management/get-hotfix

**Microsoft Intune** — *Devices → All devices → Export* (OS, OS version, last check-in). **RMM tools** (NinjaOne, Atera, etc.) — export the patch/device report and map the columns.

**Mac / iPad / phone** — *Settings → General → About* shows the version; type it in.

**Router** — the admin page shows the model and firmware version.
