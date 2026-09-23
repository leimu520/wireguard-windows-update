<#
.SYNOPSIS
    Deploy the build produced by build-amd64.sh over an existing WireGuard
    installation, or put the original executable back.

.DESCRIPTION
    Overwriting the installed executable is enough: the tunnel configurations,
    the WireGuardNT driver and the services all stay as they are, because only
    wireguard.exe is replaced and it talks to the driver through the same
    interface the official build does.

    Two things this script does that a plain copy does not:

      * it stops the services and waits for the last wireguard.exe process to
        exit first. Windows lets you overwrite a running executable, so a copy
        over a live installation appears to succeed while the old code keeps
        running until something restarts the service. That failure is silent and
        easy to mistake for the new build being broken;
      * it checks the hash of what landed on disk against the source, and
        reports the process start times afterwards so "it is actually running
        the new one" is verifiable rather than assumed.

    The original executable is kept as wireguard.exe.orig-<version> next to it
    and is never overwritten, so -Restore always goes back to the same file.

.PARAMETER Source
    Path to the wireguard.exe to install. Defaults to amd64\wireguard.exe next
    to this script.

.PARAMETER InstallDir
    Installation directory. Defaults to %ProgramFiles%\WireGuard.

.PARAMETER Restore
    Put the backed-up original executable back instead of installing.

.PARAMETER Force
    Skip the "are you sure" prompt.

.EXAMPLE
    .\deploy-zhuanban.ps1
    Install the build in this repository over the installed one.

.EXAMPLE
    .\deploy-zhuanban.ps1 -Restore
    Roll back to the official executable that was there before.
#>
[CmdletBinding()]
param(
    [string] $Source,
    [string] $InstallDir = (Join-Path $env:ProgramFiles 'WireGuard'),
    [switch] $Restore,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this from an elevated PowerShell: it stops and starts Windows services and writes to Program Files.'
    }
}

function Get-WireGuardServices {
    $names = @()
    $names += Get-Service -Name 'WireGuardManager' -ErrorAction SilentlyContinue
    $names += Get-Service -Name 'WireGuardTunnel$*' -ErrorAction SilentlyContinue
    return @($names)
}

function Stop-WireGuard {
    # Remember which services were running so they can be put back the same way:
    # a tunnel the user had stopped should stay stopped.
    $running = @()
    foreach ($service in Get-WireGuardServices) {
        if ($service.Status -eq 'Running') { $running += $service.Name }
    }
    foreach ($service in Get-WireGuardServices) {
        if ($service.Status -ne 'Stopped') {
            Write-Host ("  stopping " + $service.Name)
            Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
        }
    }
    # The services exit first; any process still holding the file after that is
    # a tray UI or a leftover, and the copy below needs the file free.
    Start-Sleep -Seconds 2
    Get-CimInstance Win32_Process -Filter "Name='wireguard.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host ("  ending leftover process " + $_.ProcessId)
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2
    $left = @(Get-CimInstance Win32_Process -Filter "Name='wireguard.exe'" -ErrorAction SilentlyContinue).Count
    if ($left -ne 0) {
        throw ("$left wireguard.exe process(es) are still running, so the executable cannot be replaced.")
    }
    return @($running)
}

function Start-WireGuard($previouslyRunning) {
    if ($previouslyRunning -contains 'WireGuardManager') {
        Write-Host '  starting WireGuardManager'
        Start-Service -Name 'WireGuardManager'
        Start-Sleep -Seconds 3
    }
    foreach ($name in $previouslyRunning) {
        if ($name -eq 'WireGuardManager') { continue }
        Write-Host ("  starting " + $name)
        Start-Service -Name $name -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 5
}

function Show-State {
    Write-Host ''
    Write-Host 'Services:'
    Get-WireGuardServices | Select-Object Name, Status | Format-Table -AutoSize
    Write-Host 'Processes:'
    Get-CimInstance Win32_Process -Filter "Name='wireguard.exe'" -ErrorAction SilentlyContinue |
        Select-Object ProcessId, CreationDate, @{ n = 'role'; e = {
                if ($_.CommandLine -like '*tunnelservice*') { 'tunnel' }
                elseif ($_.CommandLine -like '*managerservice*') { 'manager' }
                else { 'ui' }
            } } | Format-Table -AutoSize
}

Assert-Administrator

$installed = Join-Path $InstallDir 'wireguard.exe'
if (-not (Test-Path -LiteralPath $installed)) {
    throw ("WireGuard does not look installed: $installed is missing. Install the official build first, then run this to put the modified executable over it.")
}

if (-not $Source) {
    $Source = Join-Path $PSScriptRoot 'amd64\wireguard.exe'
}

if ($Restore) {
    $backup = Get-ChildItem -LiteralPath $InstallDir -Filter 'wireguard.exe.orig-*' -ErrorAction SilentlyContinue |
        Sort-Object Name | Select-Object -First 1
    if (-not $backup) {
        throw ("No backup found in $InstallDir (expected wireguard.exe.orig-*). Nothing to restore; reinstall the official build instead.")
    }
    Write-Host ("Restoring " + $backup.FullName)
    $sourceHash = (Get-FileHash -LiteralPath $backup.FullName).Hash
} else {
    if (-not (Test-Path -LiteralPath $Source)) {
        throw ("Build not found: $Source. Run build-amd64.sh first.")
    }
    Write-Host ("Installing " + $Source)
    $sourceHash = (Get-FileHash -LiteralPath $Source).Hash
}

if (-not $Force) {
    Write-Host ''
    Write-Host ("  from: " + $(if ($Restore) { $backup.FullName } else { $Source }))
    Write-Host ("  to:   " + $installed)
    Write-Host ("  hash: " + $sourceHash)
    Write-Host ''
    Write-Host 'Active tunnels will drop for a few seconds while the services restart.'
    $answer = Read-Host 'Continue? [y/N]'
    if ($answer -notmatch '^[Yy]') {
        Write-Host 'Aborted.'
        return
    }
}

# Keep one copy of the original, made the first time this runs.
if (-not $Restore) {
    $existing = Get-ChildItem -LiteralPath $InstallDir -Filter 'wireguard.exe.orig-*' -ErrorAction SilentlyContinue
    if (-not $existing) {
        $version = (Get-Item -LiteralPath $installed).VersionInfo.FileVersion
        if (-not $version) { $version = 'unknown' }
        $backupPath = Join-Path $InstallDir ('wireguard.exe.orig-' + $version)
        Write-Host ("Backing up the current executable to " + $backupPath)
        Copy-Item -LiteralPath $installed -Destination $backupPath
        Write-Host ("  backup hash: " + (Get-FileHash -LiteralPath $backupPath).Hash)
    } else {
        Write-Host ("Existing backup kept: " + $existing[0].FullName)
    }
}

Write-Host 'Stopping WireGuard:'
$wasRunning = Stop-WireGuard

Write-Host 'Replacing the executable:'
if ($Restore) {
    Copy-Item -LiteralPath $backup.FullName -Destination $installed -Force
} else {
    Copy-Item -LiteralPath $Source -Destination $installed -Force
}
$landed = (Get-FileHash -LiteralPath $installed).Hash
if ($landed -ne $sourceHash) {
    throw ("The file on disk does not match the source. Expected $sourceHash, found $landed.")
}
Write-Host ("  installed hash: " + $landed + " (matches source)")

Write-Host 'Starting WireGuard:'
Start-WireGuard $wasRunning

Show-State
Write-Host ''
Write-Host 'Done. To confirm the reconnect watchdog started, from an elevated PowerShell:'
Write-Host '    & "$env:ProgramFiles\WireGuard\wireguard.exe" /dumplog > "$env:TEMP\wg.txt"'
Write-Host '    Select-String Auto-reconnect "$env:TEMP\wg.txt" | Select-Object -Last 5'
Write-Host 'The line to look for names the endpoint and the probe target, for example:'
Write-Host '    Auto-reconnect: watching <host>, probing <host:port> over http every 5s (timeout 3s, 3 failures in a row before acting)'
Write-Host ''
Write-Host 'To put the original executable back:  .\deploy-zhuanban.ps1 -Restore'
