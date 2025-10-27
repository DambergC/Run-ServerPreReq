<img width="863" height="515" alt="image" src="https://github.com/user-attachments/assets/28c28d67-5d9b-42bf-83ef-94f5b147ae22" />

# Run-PreReqServer.ps1

A PowerShell script to prepare a Windows server with common prerequisites required by Visma services.

This script automates downloading, verifying and (optionally) silently installing several common components used by Visma server components (Integration services, web hosts, batch servers, etc.). It can also configure regional/language settings, create folders and a local group, and keep installers for later use.

viw is short for VismaWindow.

---

## Quick summary

- Platform: Windows (PowerShell)
- Requires: Administrator privileges (script checks for elevation)
- Purpose: Download and install prerequisites such as:
  - .NET Framework 4.8
  - ASP.NET Core 8 Hosting Bundle
  - Visual C++ Redistributables (x86/x64)
  - Microsoft ODBC Driver 17 for SQL Server
  - Microsoft OLE DB Driver 18 (requires version check >= 18.6.5)
- Supports modes for different server roles (viw / batch / puf / AllInOne)
- Default download folder: `D:\visma\Install\Serverdownloads`
- Default backup folder: `D:\visma\Install\Backup`
- Default log file: `$Destination\install.log`

---

## Requirements

- Run as an Administrator (the script checks for elevation and exits if not elevated).
- PowerShell with ability to run scripts and access to the Internet for downloads.
- TLS 1.2 enabled for downloads (the script enables TLS1.2/1.1/1.0 in the session).

---

## How it works (high-level)

- Ensures destination and backup folders exist (or creates them).
- Ensures a local group called "Visma Services Trusted Users" exists and tries to add the current user.
- Provides a `Download-File` helper to download files using Invoke-WebRequest and falls back to BITS if needed. Optionally verifies Authenticode signatures.
- Detects whether components are already installed (registry checks, DLL presence, file-version checks).
- Downloads required installers to the destination folder and runs them silently (unless `-DryRun` is used).
- Optionally configures locale/language/home location when `-ConfirmLocaleChange` is specified.
- Keeps installer files in the destination folder for later reuse (no automatic deletion).

---

## Modes

Only one mode may be selected at a time. `-AllInOne` is mutually exclusive with `-viw`, `-batch`, and `-puf`.

- `-viw`  
  Short for VismaWindow (viw). Installs only the prerequisites intended for VismaWindow type servers.
- `-batch`  
  Installs prerequisites for batch servers.
- `-puf`  
  Installs prerequisites for PUF servers.
- `-AllInOne`  
  Runs the full set of prerequisites (equivalent to running viw + batch + puf). Do not combine `-AllInOne` with any of `-viw`, `-batch` or `-puf`.

If no mode is selected the script logs a warning and will run only common tasks.

---

## Parameters

- `[switch] $viw`  
- `[switch] $batch`  
- `[switch] $puf`  
- `[switch] $AllInOne`  
- `[string] $Destination`  
  - Path where installers and temporary downloads are stored.  
  - Default: `D:\visma\Install\Serverdownloads`  
- `[string] $BackupFolder`  
  - Path where backup scripts and additional downloaded items are saved.  
  - Default: `D:\visma\Install\Backup`  
- `[switch] $ConfirmLocaleChange`  
  - Opt-in to change user culture, system locale, language list and home location to the target region (`sv-SE` by default).
- `[switch] $DryRun`  
  - When set, the script prints/logs actions it would perform but does not download or run installers or change system settings.
- `[string] $LogFile`  
  - Optional full path to a log file. If not provided the script creates `$Destination\install.log`.

---

## What it installs / checks

- .NET Framework 4.8  
  - Detection: registry Release value under `HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full`
- ASP.NET Core 8 Hosting Bundle  
  - Detection: checks installed shared frameworks for any folder beginning with `8.`
- Visual C++ Redistributables (x86 and x64)  
  - Detection: registry uninstall entries or presence of common runtime DLLs
- Microsoft ODBC Driver 17 for SQL Server  
  - Detection: ODBC registry keys under `HKLM:\SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers` and specific driver keys
- Microsoft OLE DB Driver 18  
  - Detection: uninstall registry entries for "OLE DB Driver", or searching for `msoledbsql.dll` and checking file version; requires version >= 18.6.5

Additional: the script contains a helper to ensure `PersonecPRegFix.exe` is present in the destination (download from releases if not present) and also attempts to download `CygateScript.ps1` to the backup folder if missing.

---

## Signature verification

- The `Download-File` helper can optionally verify Authenticode signatures (`-VerifySignature`).
- The script uses this verification when downloading certain installers. If verification fails the script will warn but may continue depending on the logic.

---

## Logging

- The script writes logs to the specified `$LogFile` (default: `$Destination\install.log`).
- Log lines include a timestamp and level (INFO, WARN, ERROR, SUCCESS, DEBUG).
- Console output is colorized for easier reading.

---

## Examples

- Dry run for PUF servers:
  - `.\Run-PreReqServer.ps1 -puf -DryRun`
- Run all prerequisites and allow locale changes (non-interactive):
  - `.\Run-PreReqServer.ps1 -AllInOne -ConfirmLocaleChange`
- Run only VismaWindow installs and write log to custom file:
  - `.\Run-PreReqServer.ps1 -viw -LogFile "C:\temp\visma_install.log"`
- Run full install into a different destination folder:
  - `.\Run-PreReqServer.ps1 -AllInOne -Destination "C:\Install\Serverdownloads"`

---

## Troubleshooting helper (small PowerShell script)

Below is a small troubleshooting script you can save as `Parse-InstallLog.ps1`. It parses the install log for ERROR/WARN lines, counts occurrences, shows the last errors and warns if restart-required exit codes are detected.

To use:
- Save to `Parse-InstallLog.ps1`
- Run: `.\Parse-InstallLog.ps1 -LogFile "D:\visma\Install\Serverdownloads\install.log"`

```powershell
<#
.SYNOPSIS
  Parse install log and report failures/warnings.

.PARAMETER LogFile
  Path to the install log (defaults to D:\visma\Install\Serverdownloads\install.log)

.EXAMPLE
  .\Parse-InstallLog.ps1 -LogFile "D:\visma\Install\Serverdownloads\install.log"
#>

param(
    [string]$LogFile = "D:\visma\Install\Serverdownloads\install.log",
    [int]$TailLines = 200
)

if (-not (Test-Path $LogFile)) {
    Write-Host "Log file not found: $LogFile" -ForegroundColor Red
    exit 2
}

$lines = Get-Content -Path $LogFile -ErrorAction Stop

$errors = $lines | Where-Object { $_ -match '\[ERROR\]' }
$warns  = $lines | Where-Object { $_ -match '\[WARN\]' }
$success = $lines | Where-Object { $_ -match '\[SUCCESS\]' }
$debug = $lines | Where-Object { $_ -match '\[DEBUG\]' }

Write-Host "Log summary for: $LogFile" -ForegroundColor Cyan
Write-Host "Total lines: $($lines.Count)"
Write-Host "ERROR: $($errors.Count)   WARN: $($warns.Count)   SUCCESS: $($success.Count)   DEBUG: $($debug.Count)"

if ($errors.Count -gt 0) {
    Write-Host "`nLast errors (up to $TailLines lines):" -ForegroundColor Red
    $errors | Select-Object -Last 20 | ForEach-Object { Write-Host $_ -ForegroundColor Red }
}

if ($warns.Count -gt 0) {
    Write-Host "`nRecent warnings:" -ForegroundColor Yellow
    $warns | Select-Object -Last 20 | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
}

# Detect common installer exit codes/actions in the log lines
$restartNeeded = $lines | Where-Object { $_ -match '3010' -or $_ -match 'restart required' -or $_ -match 'restart may be required' }
if ($restartNeeded) {
    Write-Host "`nNote: One or more installations indicate that a restart is required." -ForegroundColor Yellow
}

# Return exit code 1 if there were any ERROR lines
if ($errors.Count -gt 0) { exit 1 } else { exit 0 }
```

---

## CHANGELOG (short)

- 2025-10-27 - Changed colors in output and added download of PersonecPregfix.exe
- 2025-10-24 — Added improved OLE DB Driver 18 version checks, added Authenticode verification for downloads, improved logging; modularized installs and added DryRun support.
- 2025-10-15 — Initial script that downloads and installs the common Visma server prerequisites.

---

## Troubleshooting / FAQ

- Not running as Administrator  
  Re-run from an elevated PowerShell session.
- Downloads failing  
  Ensure outbound HTTPS access is allowed. Script tries Invoke-WebRequest then BITS as fallback.
- Signature verification warnings  
  Check the certificate chain and whether the installer is signed.
- Installer exit codes  
  - 0 = success  
  - 3010 = success but restart required  
  - 1638 = another version already present (Visual C++ installer)
- Locale changes not applied  
  Ensure `-ConfirmLocaleChange` was provided; some changes require a restart.

---

## Files & locations

- Main script: `Run-PreReqServer.ps1`
- Default downloads: `D:\visma\Install\Serverdownloads`
- Default backups: `D:\visma\Install\Backup`
- Example backup download: `CygateScript.ps1` saved to the backup folder
- `PersonecPRegFix.exe`: downloaded to the destination folder if missing (from this repo's releases)

---

## Author / License

- Maintainer: DambergC  
- Repository: https://github.com/DambergC/Run-ServerPreReq  
- Last modified: 2025-10-24 (as recorded in script header)  
- License: See repository LICENSE (if present)

```
