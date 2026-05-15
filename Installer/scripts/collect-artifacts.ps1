[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$StageRoot = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'artifacts\staging'),
    [switch]$DownloadVcRedist
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRootPath = (Resolve-Path $RepoRoot).Path
$releaseDir = Join-Path $repoRootPath 'x64\Release'
$trayAppSource = Join-Path $releaseDir 'TrayApp.exe'
$trayServiceSource = Join-Path $releaseDir 'TrayService.exe'
$appStageDir = Join-Path $StageRoot 'app'
$depsStageDir = Join-Path $StageRoot 'deps'

if (-not (Test-Path $trayAppSource -PathType Leaf)) {
    throw "TrayApp.exe was not found at $trayAppSource. Build Release|x64 first."
}

if (-not (Test-Path $trayServiceSource -PathType Leaf)) {
    throw "TrayService.exe was not found at $trayServiceSource. Build Release|x64 first."
}

if (Test-Path $appStageDir) {
    Remove-Item -LiteralPath $appStageDir -Recurse -Force
}

New-Item -ItemType Directory -Path $appStageDir -Force | Out-Null
Copy-Item -LiteralPath $trayAppSource -Destination (Join-Path $appStageDir 'TrayApp.exe') -Force
Copy-Item -LiteralPath $trayServiceSource -Destination (Join-Path $appStageDir 'TrayService.exe') -Force

$trayServiceInfo = Get-Item -LiteralPath $trayServiceSource
$timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
Write-Host "[$timestamp] Staged TrayService.exe from $($trayServiceInfo.FullName)"
Write-Host "TrayService.exe source last write time (UTC): $($trayServiceInfo.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))"

if ($DownloadVcRedist) {
    New-Item -ItemType Directory -Path $depsStageDir -Force | Out-Null
    $vcRedistPath = Join-Path $depsStageDir 'VC_redist.x64.exe'
    $vcRedistUrl = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'
    Invoke-WebRequest -Uri $vcRedistUrl -OutFile $vcRedistPath
    Write-Host "Downloaded VC++ Redistributable to $vcRedistPath"
}
