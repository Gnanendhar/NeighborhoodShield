# endpoint_protection.csv — antivirus, encryption, screen lock

**Why:** finds devices with protection off or out of date, laptops and phones without encryption, devices that never lock, and devices that have gone missing (CIS v8.1 1.1, 3.6, 4.3, 10.1, 10.2).

| Column | Allowed values | Notes |
|---|---|---|
| device_id | label | match the label used in patch_inventory |
| device_type | `desktop` `laptop` `tablet` `phone` `server` | |
| protection_product | text or empty | Empty on a computer = "no antivirus" finding |
| protection_enabled | `Y` `N` | real-time protection on |
| definitions_date | YYYY-MM-DD | older than 7 days = finding |
| disk_encryption | `Y` `N` `unknown` | BitLocker / FileVault / phone passcode encryption |
| screen_lock | `Y` `N` `unknown` | locks automatically |
| last_seen_date | YYYY-MM-DD | last time the device was used or checked in |

## How to export

**Windows with Microsoft Defender** — run `export_scripts/Export-NSLocalDevice.ps1` (uses `Get-MpComputerStatus`: `AntivirusEnabled`, `RealTimeProtectionEnabled`, `AntivirusSignatureLastUpdated`; and `Get-BitLockerVolume`). Docs: https://learn.microsoft.com/powershell/module/defender/get-mpcomputerstatus

**Microsoft Defender portal / Intune** — *Endpoints → Device inventory → Export*. **CrowdStrike Falcon** — *Host management → Export* (sensor status, last seen). **Other antivirus consoles** — export the device list to CSV and map the columns.

**Phones and tablets** — iPhones/iPads with a passcode are encrypted (`Y`). Android: *Settings → Security → Encryption*.
