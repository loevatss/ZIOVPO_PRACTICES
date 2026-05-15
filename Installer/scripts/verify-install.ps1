[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'verify-install.ps1 must be run from an elevated administrator session.'
    }
}

function Wait-ServiceState {
    param(
        [string]$Name,
        [string]$ExpectedStatus,
        [int]$TimeoutSeconds = 60
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            if ($ExpectedStatus -eq 'Absent') {
                return
            }
        }
        elseif ($service.Status.ToString() -eq $ExpectedStatus) {
            return
        }

        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)

    throw "Service '$Name' did not reach state '$ExpectedStatus' within $TimeoutSeconds seconds."
}

Assert-Admin

$installerFullPath = (Resolve-Path $InstallerPath).Path
$isBundle = [IO.Path]::GetExtension($installerFullPath).Equals('.exe', [StringComparison]::OrdinalIgnoreCase)
$serviceName = 'AntivirusService'
$installDir = Join-Path ${env:ProgramFiles} 'ZIOVPO Antivirus'
$programDataDbDir = Join-Path ${env:ProgramData} 'Antivirus\Databases'
$trayAppPath = Join-Path $installDir 'TrayApp.exe'
$trayServicePath = Join-Path $installDir 'TrayService.exe'
$defaultDbPath = Join-Path $programDataDbDir 'default.avdb'
$tempRoot = Join-Path $env:TEMP 'ziovpo-antivirus-installer-verify'
$installLog = Join-Path $tempRoot 'install.log'
$uninstallLog = Join-Path $tempRoot 'uninstall.log'

New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

if ($isBundle) {
    Start-Process -FilePath $installerFullPath -ArgumentList '/install', '/quiet', '/norestart', '/log', $installLog -Wait -NoNewWindow
}
else {
    Start-Process -FilePath 'msiexec.exe' -ArgumentList '/i', ('"' + $installerFullPath + '"'), '/qn', '/norestart', '/l*v', ('"' + $installLog + '"') -Wait -NoNewWindow
}

if (-not (Test-Path $trayAppPath -PathType Leaf)) {
    throw "TrayApp.exe was not installed to $trayAppPath"
}

if (-not (Test-Path $trayServicePath -PathType Leaf)) {
    throw "TrayService.exe was not installed to $trayServicePath"
}

Wait-ServiceState -Name $serviceName -ExpectedStatus 'Running'

$service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
if ($null -eq $service) {
    throw "Service '$serviceName' was not registered in SCM."
}

if ($service.PathName -notmatch [Regex]::Escape($trayServicePath)) {
    throw "Service '$serviceName' binary path does not point to installed TrayService.exe. Actual: $($service.PathName)"
}

if ($service.StartMode -ne 'Auto') {
    throw "Service '$serviceName' is expected to be Auto start, actual: $($service.StartMode)"
}

if (-not (Test-Path $defaultDbPath -PathType Leaf)) {
    throw "Default antivirus database file was not created at $defaultDbPath"
}

$sdshowOutput = & sc.exe sdshow $serviceName
Write-Host ($sdshowOutput | Out-String).Trim()

$sddl = ($sdshowOutput | Select-Object -Last 1).Trim()
if ($sddl -match '\(D;[^)]*;;;BU\)') {
    throw 'Service DACL still contains a DENY ACE for BUILTIN\Users.'
}

if ($sddl -match '\(D;[^)]*;;;BA\)') {
    throw 'Service DACL still contains a DENY ACE for BUILTIN\Administrators.'
}

Stop-Service -Name $serviceName -ErrorAction Stop
Wait-ServiceState -Name $serviceName -ExpectedStatus 'Stopped'
Start-Service -Name $serviceName -ErrorAction Stop
Wait-ServiceState -Name $serviceName -ExpectedStatus 'Running'

if ($isBundle) {
    Start-Process -FilePath $installerFullPath -ArgumentList '/uninstall', '/quiet', '/norestart', '/log', $uninstallLog -Wait -NoNewWindow
}
else {
    Start-Process -FilePath 'msiexec.exe' -ArgumentList '/x', ('"' + $installerFullPath + '"'), '/qn', '/norestart', '/l*v', ('"' + $uninstallLog + '"') -Wait -NoNewWindow
}

Wait-ServiceState -Name $serviceName -ExpectedStatus 'Absent'

if (Test-Path $installDir) {
    throw "Install directory still exists after uninstall: $installDir"
}

if (Select-String -Path $uninstallLog -Pattern 'Service could not be stopped' -SimpleMatch -Quiet) {
    throw "Uninstall log contains 'Service could not be stopped'. See $uninstallLog"
}

Write-Host 'Install/uninstall verification completed successfully.'
