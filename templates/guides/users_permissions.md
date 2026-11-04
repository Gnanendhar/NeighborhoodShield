# users_permissions.csv — logins and permissions

**Why:** finds shared logins, admins without multi-factor authentication (MFA), former staff, and accounts no one has used in 90+ days (CIS v8.1 safeguards 5.1–5.4, 6.2–6.5).

| Column | Allowed values | Notes |
|---|---|---|
| user_id | any label | Use `owner`, `cashier-1`, not real names. Hashed on upload. |
| account_type | `staff` `admin` `service` `shared` | `shared` = more than one person uses it |
| is_admin | `Y` `N` | Can install software / manage users |
| mfa_enabled | `Y` `N` `unknown` | Asks for a code or app approval |
| status | `active` `disabled` | |
| created_date | YYYY-MM-DD | optional |
| last_login_date | YYYY-MM-DD | Drives the dormant-account check |
| role_or_department | text | Empty = "no known owner" finding |

## How to export

**Microsoft 365 / Entra ID** — Entra admin center → *Users* → *All users* → *Download users*. That file has `accountEnabled`, `userType`, and `createdDateTime`. For MFA use *Authentication methods* → *User registration details* → *Download* (`isMfaRegistered`, `isAdmin`). For last sign-in, add the `lastSignInDateTime` column in the users list (needs Entra ID P1) or use the sign-in logs. Map: `accountEnabled` → status, `isAdmin` → is_admin, `isMfaRegistered` → mfa_enabled.
Docs: https://learn.microsoft.com/entra/identity/users/users-bulk-download

**Google Workspace** — Admin console → *Directory* → *Users* → *Download users* (all columns). Map: `Status [READ ONLY]` → status, `Last Sign In [READ ONLY]` → last_login_date, `2sv Enrolled [READ ONLY]` → mfa_enabled. Admin role is shown in *Admin roles*; mark those users `is_admin = Y`.
Docs: https://support.google.com/a/answer/7348070

**Active Directory** — run `export_scripts/Export-NSADUsers.ps1`, which wraps `Get-ADUser` and the Domain Admins / Administrators group membership and writes this template with labels. Docs: https://learn.microsoft.com/powershell/module/activedirectory/get-aduser

**No system at all** — fill it in by hand: one row for each login to email, the register, the bank, and booking. That alone is a CIS 5.1 account inventory.
