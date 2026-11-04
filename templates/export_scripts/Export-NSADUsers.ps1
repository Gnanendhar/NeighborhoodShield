<#
.SYNOPSIS
    Read-only export of Active Directory users in NeighborhoodShield format (users_permissions.csv).

.DESCRIPTION
    Uses Get-ADUser and privileged-group membership to build the template. Real account
    names are replaced by labels (user-001, user-002 ...). A separate key file that maps
    labels back to account names is written next to the export FOR THE OWNER ONLY:
    keep it, never upload it.

    Notes for the contractor:
      * LastLogonDate is derived from lastLogonTimestamp, which replicates with up to
        ~14 days of lag. Good enough for a 90-day dormant check, not for forensics.
      * On-premises AD has no MFA attribute. mfa_enabled is written as "unknown";
        set it from your MFA provider (Entra ID, Duo, etc.) if you have one.

.EXAMPLE
    .\Export-NSADUsers.ps1 -OutDir C:\ns_export

.NOTES
    Part of NeighborhoodShield AI (ChiEAC). Requires the RSAT ActiveDirectory module.
    Status: Week 1 draft. Validate against the builder's lab domain before publishing.
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path -Path (Get-Location) -ChildPath 'neighborhoodshield_export'),
    [string[]]$AdminGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators'),
    [string]$SharedAccountPattern = '^(shared|front|frontdesk|register|pos|kiosk|reception|staff)\b'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Format-NSDate($d) { if ($d) { ([datetime]$d).ToString('yyyy-MM-dd') } else { '' } }

$adminSids = @{}
foreach ($g in $AdminGroups) {
    try {
        Get-ADGroupMember -Identity $g -Recursive | Where-Object objectClass -eq 'user' |
            ForEach-Object { $adminSids[$_.SID.Value] = $true }
    } catch { Write-Verbose "Group '$g' not found; skipping." }
}

$props = 'Enabled', 'LastLogonDate', 'whenCreated', 'Department', 'Title', 'ServicePrincipalName'
$users = Get-ADUser -Filter * -Properties $props | Sort-Object SamAccountName

$i = 0
$rows = foreach ($u in $users) {
    $i++
    $label = 'user-{0:d3}' -f $i
    $isAdmin = $adminSids.ContainsKey($u.SID.Value)
    $type = if (@($u.ServicePrincipalName).Count -gt 0 -and $u.ServicePrincipalName) { 'service' }
            elseif ($u.SamAccountName -match $SharedAccountPattern) { 'shared' }
            elseif ($isAdmin -and $u.SamAccountName -match '(adm|admin)') { 'admin' }
            else { 'staff' }
    [pscustomobject][ordered]@{
        _key               = $u.SamAccountName
        user_id            = $label
        account_type       = $type
        is_admin           = if ($isAdmin) { 'Y' } else { 'N' }
        mfa_enabled        = 'unknown'
        status             = if ($u.Enabled) { 'active' } else { 'disabled' }
        created_date       = Format-NSDate $u.whenCreated
        last_login_date    = Format-NSDate $u.LastLogonDate
        role_or_department = if ($u.Department) { $u.Department } elseif ($u.Title) { $u.Title } else { '' }
    }
}

$exportFile = Join-Path $OutDir 'users_permissions.csv'
$keyFile = Join-Path $OutDir 'KEEP_PRIVATE_user_label_key.csv'
$rows | Select-Object * -ExcludeProperty _key | Export-Csv -Path $exportFile -NoTypeInformation -Encoding UTF8
$rows | Select-Object user_id, @{ n = 'account_name'; e = { $_._key } } | Export-Csv -Path $keyFile -NoTypeInformation -Encoding UTF8

Write-Host "Wrote $exportFile  ($($rows.Count) accounts, $($adminSids.Count) in admin groups)"
Write-Host "Wrote $keyFile  <- keep this file private. Do NOT upload it."
