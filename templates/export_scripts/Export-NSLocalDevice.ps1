<#
.SYNOPSIS
    Read-only export of THIS Windows computer's update and protection status,
    in NeighborhoodShield template format (patch_inventory.csv + endpoint_protection.csv).

.DESCRIPTION
    Reads (never changes) the operating system version, latest installed update,
    Windows Update policy, pending updates, antivirus status, BitLocker status and
    screen-lock policy. Writes two CSV files that use a label, not the computer name.

    Run only on a computer you own or are authorized to assess.
    Run as administrator to include BitLocker status (otherwise it is reported as "unknown").

.EXAMPLE
    .\Export-NSLocalDevice.ps1 -DeviceLabel office-pc -KeySoftwareName "QuickBooks Desktop" -KeySoftwareVersion 2021

.NOTES
    Part of NeighborhoodShield AI (ChiEAC). Tested target: Windows 10 22H2 / Windows 11, Windows PowerShell 5.1 and PowerShell 7.
    Status: Week 1 draft. Validate on the builder's own lab machine before publishing in the user guide.
#>
[CmdletBinding()]
param(
    [string]$DeviceLabel = 'pc-1',
    [ValidateSet('desktop', 'laptop', 'server')]
    [string]$DeviceType,
    [string]$OutDir = (Join-Path -Path (Get-Location) -ChildPath 'neighborhoodshield_export'),
    [string]$KeySoftwareName = '',
    [string]$KeySoftwareVersion = '',
    [ValidateSet('Y', 'N', 'unknown')]
    [string]$KeySoftwareSupported = 'unknown',
    [switch]$SkipUpdateSearch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Format-NSDate($d) {
    if ($null -eq $d -or $d -eq '') { return '' }
    try { return ([datetime]$d).ToString('yyyy-MM-dd') } catch { return '' }
}

$today = (Get-Date).ToString('yyyy-MM-dd')
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------- OS version
$os = Get-CimInstance -ClassName Win32_OperatingSystem
$cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$build = [int]$cv.CurrentBuild
$major = if ($build -ge 22000) { '11' } else { '10' }   # Windows 11 still reports "10.0" as its version
$display = if ($cv.PSObject.Properties.Name -contains 'DisplayVersion') { $cv.DisplayVersion } else { $cv.ReleaseId }
$edition = $cv.EditionID   # Core = Home, Professional = Pro, Enterprise, Education ...
$osVersion = "$major $display"
$osName = if ($os.ProductType -ne 1) { 'Windows Server' } else { 'Windows' }

if (-not $DeviceType) {
    $laptopChassis = 8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32
    $chassis = (Get-CimInstance -ClassName Win32_SystemEnclosure).ChassisTypes
    $DeviceType = if ($os.ProductType -ne 1) { 'server' }
                  elseif ($chassis | Where-Object { $laptopChassis -contains $_ }) { 'laptop' }
                  else { 'desktop' }
}

# ------------------------------------------------------------------ updates
$lastHotfix = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
$au = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
$autoUpdate = if ($au -and ($au.PSObject.Properties.Name -contains 'NoAutoUpdate') -and $au.NoAutoUpdate -eq 1) { 'N' } else { 'Y' }

$pendingCritical = 0
if (-not $SkipUpdateSearch) {
    try {
        Write-Host 'Searching for pending updates (read-only, can take a minute)...'
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $pendingCritical = @($result.Updates | Where-Object {
            $_.MsrcSeverity -eq 'Critical' -or (@($_.Categories) | Where-Object { $_.Name -eq 'Security Updates' })
        }).Count
    } catch {
        Write-Warning "Could not query Windows Update ($($_.Exception.Message)). pending_critical_updates set to 0."
    }
}

# --------------------------------------------------------------- antivirus
# Prefer the product registered with Windows Security Center (covers third-party AV);
# fall back to Microsoft Defender's own status.
$product = ''; $enabled = 'N'; $defs = ''
$avList = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue)
foreach ($av in $avList) {
    $hex = '{0:x6}' -f [int]$av.productState
    $isOn = $hex.Substring(2, 2) -in @('10', '11')      # scanner state byte
    if ($isOn -or -not $product) {
        $product = $av.displayName
        $enabled = if ($isOn) { 'Y' } else { 'N' }
    }
}
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mp -and ($product -eq '' -or $product -like '*Defender*')) {
    $product = 'Microsoft Defender Antivirus'
    $enabled = if ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) { 'Y' } else { 'N' }
    $defs = Format-NSDate $mp.AntivirusSignatureLastUpdated
}

# -------------------------------------------------------------- encryption
$encryption = 'unknown'
if ($isAdmin) {
    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive
        $encryption = if ($bl.ProtectionStatus -eq 'On') { 'Y' } else { 'N' }
    } catch { $encryption = 'unknown' }
} else {
    Write-Warning 'Not running as administrator: disk_encryption reported as unknown.'
}

# ------------------------------------------------------------- screen lock
# Y when a machine inactivity limit or a password-protected screen saver of 15 minutes or less is set.
# Otherwise "unknown" (a sleep timeout with sign-in on wake may still lock the device).
$screenLock = 'unknown'
$pol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
if ($pol -and ($pol.PSObject.Properties.Name -contains 'InactivityTimeoutSecs') -and $pol.InactivityTimeoutSecs -gt 0 -and $pol.InactivityTimeoutSecs -le 900) {
    $screenLock = 'Y'
}
$desk = Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -ErrorAction SilentlyContinue
if ($desk -and ($desk.PSObject.Properties.Name -contains 'ScreenSaverIsSecure') -and $desk.ScreenSaverIsSecure -eq '1' `
        -and ($desk.PSObject.Properties.Name -contains 'ScreenSaveTimeOut') -and [int]$desk.ScreenSaveTimeOut -le 900) {
    $screenLock = 'Y'
}

# ------------------------------------------------------------------ output
$patchRow = [pscustomobject][ordered]@{
    device_id                = $DeviceLabel
    device_type              = $DeviceType
    os_name                  = $osName
    os_version               = "$osVersion"
    auto_update_enabled      = $autoUpdate
    last_patch_date          = Format-NSDate ($lastHotfix.InstalledOn)
    pending_critical_updates = $pendingCritical
    key_software_name        = $KeySoftwareName
    key_software_version     = $KeySoftwareVersion
    vendor_supported         = $KeySoftwareSupported
}
$endpointRow = [pscustomobject][ordered]@{
    device_id          = $DeviceLabel
    device_type        = $DeviceType
    protection_product = $product
    protection_enabled = $enabled
    definitions_date   = $defs
    disk_encryption    = $encryption
    screen_lock        = $screenLock
    last_seen_date     = $today
}

$patchFile = Join-Path $OutDir "patch_inventory_$DeviceLabel.csv"
$endpointFile = Join-Path $OutDir "endpoint_protection_$DeviceLabel.csv"
$patchRow | Export-Csv -Path $patchFile -NoTypeInformation -Encoding UTF8
$endpointRow | Export-Csv -Path $endpointFile -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host "Edition detected: $edition (Core = Home). Check end-of-life for Windows $osVersion at https://endoflife.date/windows"
Write-Host "Wrote $patchFile"
Write-Host "Wrote $endpointFile"
Write-Host 'Combine rows from several computers into one file per template before uploading.'
