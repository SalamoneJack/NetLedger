<#
.SYNOPSIS
    Installs NetLedger on Windows Server 2016+ / Windows 10+ as an always-on background task.

.DESCRIPTION
    Creates a Python virtual environment, installs NetLedger, writes starter configuration to
    C:\ProgramData\NetLedger (locked down to SYSTEM and Administrators) and registers a scheduled
    task that runs 'netledger serve' at startup and restarts it automatically if it stops.

.PARAMETER Source
    What to install with pip: "netledger" (default), a path to a source checkout, or a git URL.

.PARAMETER ServiceAccount
    Account the task runs as. Default SYSTEM. Use a group managed service account such as
    "CORP\svc-netledger$" to reach devices or Git with domain credentials.

.PARAMETER Uninstall
    Removes the scheduled task and program files. Configuration and data are kept.

.EXAMPLE
    # From an elevated PowerShell prompt in the repository folder:
    Set-ExecutionPolicy -Scope Process Bypass
    .\deploy\windows\install.ps1 -Source .
#>
[CmdletBinding()]
param(
    [string]$Source = "netledger",
    [string]$InstallDir = "$env:ProgramFiles\NetLedger",
    [string]$DataDir = "$env:ProgramData\NetLedger",
    [string]$ServiceAccount = "SYSTEM",
    [string]$Python = "",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$TaskName = "NetLedger"

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated (Administrator) PowerShell prompt."
}

if ($Uninstall) {
    Write-Host "Removing scheduled task and program files..."
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $task) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
    Write-Host "Removed. Configuration and data were kept in $DataDir."
    return
}

# --- Python -------------------------------------------------------------------------------
if (-not $Python) {
    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($null -ne $launcher) {
        $Python = (& py -3 -c "import sys; print(sys.executable)").Trim()
    } else {
        $cmd = Get-Command python -ErrorAction SilentlyContinue
        if ($null -eq $cmd) { throw "Python 3.9+ was not found. Install it from https://www.python.org/downloads/windows/ (tick 'Add to PATH')." }
        $Python = $cmd.Source
    }
}
& $Python -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"
if ($LASTEXITCODE -ne 0) { throw "Python 3.9 or newer is required ($Python)." }
if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Warning "Git was not found. Install Git for Windows, or use 'git.backend: github' in netledger.yaml."
}

# --- Program ------------------------------------------------------------------------------
Write-Host "Installing NetLedger into $InstallDir ..."
& $Python -m venv $InstallDir
$venvPython = Join-Path $InstallDir "Scripts\python.exe"
& $venvPython -m pip install --quiet --upgrade pip
& $venvPython -m pip install --quiet --upgrade $Source
if ($LASTEXITCODE -ne 0) { throw "pip install failed." }
$exe = Join-Path $InstallDir "Scripts\netledger.exe"

# --- Configuration ------------------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "logs") | Out-Null
$config = Join-Path $DataDir "netledger.yaml"
if (-not (Test-Path $config)) {
    Write-Host "Writing starter configuration to $DataDir ..."
    & $exe init $DataDir | Out-Null
}
# Only SYSTEM, Administrators and the service account may read the folder (it holds secrets).
& icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
if ($ServiceAccount -ne "SYSTEM") {
    & icacls $DataDir /grant "${ServiceAccount}:(OI)(CI)M" | Out-Null
}

# --- Scheduled task -----------------------------------------------------------------------
$logFile = Join-Path $DataDir "logs\netledger.log"
$arguments = "-c `"$config`" --log-file `"$logFile`" serve"
$action = New-ScheduledTaskAction -Execute $exe -Argument $arguments -WorkingDirectory $DataDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
if ($ServiceAccount -eq "SYSTEM") {
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
} else {
    # Group managed service accounts (ending in $) need no password.
    $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType Password -RunLevel Limited
}
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
    -Description "NetLedger network configuration backup and health monitoring" -Force | Out-Null

Write-Host ""
Write-Host "NetLedger installed." -ForegroundColor Green
Write-Host ""
Write-Host "  1. Edit $config   (git.url, schedules, notifications)"
Write-Host "  2. Edit $(Join-Path $DataDir 'inventory.yaml')   (your devices)"
Write-Host "  3. Put secrets in $(Join-Path $DataDir 'netledger.env')"
Write-Host "  4. Check:  & '$exe' -c '$config' validate"
Write-Host "             & '$exe' -c '$config' test -d <device>"
Write-Host "  5. Start:  Start-ScheduledTask -TaskName $TaskName"
Write-Host "  6. Browse: http://localhost:8080/    Logs: $logFile"
