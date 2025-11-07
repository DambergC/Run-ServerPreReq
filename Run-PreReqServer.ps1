<#
.SYNOPSIS
    Prepares a Windows server with common prerequisites required by Visma services.

.DESCRIPTION
    This script downloads and installs a set of prerequisites commonly required by server
    components such as Visma Integration services. It can configure regional settings,
    create required folders and a local group, download installers (with optional signature
    verification), and run silent installs for components such as:
      - .NET Framework 4.8
      - ASP.NET Core 8 Hosting Bundle
      - Visual C++ Redistributables (x86/x64)
      - Microsoft ODBC Driver 17 for SQL Server<#
.SYNOPSIS
    Prepares a Windows server with common prerequisites required by Visma services.

.DESCRIPTION
    This script downloads and installs a set of prerequisites commonly required by server
    components such as Visma Integration services. It can configure regional settings,
    create required folders and a local group, download installers (with optional signature
    verification), and run silent installs for components such as:
      - .NET Framework 4.8
      - ASP.NET Core 8 Hosting Bundle
      - Visual C++ Redistributables (x86/x64)
      - Microsoft ODBC Driver 17 for SQL Server
      - Microsoft OLE DB Driver 18 (with version check)

    The script supports modes to install only relevant components for different server
    types (viw, batch, puf) or an all-in-one mode.

.NOTES
    - This script must be run as Administrator (the script checks for elevation).
    - By default locale changes are disabled; use -ConfirmLocaleChange to opt in.
    - Use -DryRun to show actions without executing downloads or installers.
    - The script writes logs to $Destination\install.log by default (can be overridden with -LogFile).

PARAMETER viw
    Select Visual Integration/Web (VIW) server prereqs only.

PARAMETER batch
    Select Batch server prereqs only.

PARAMETER puf
    Select PUF server prereqs only.

PARAMETER AllInOne
    Separate selection that runs all server prereqs at once. This is mutually exclusive
    with -viw, -batch and -puf. Do not combine -AllInOne with any other mode.

PARAMETER Destination
    Path where installers and temporary downloads will be stored.
    Default: D:\visma\Install\Serverdownloads

PARAMETER BackupFolder
    Path where backup scripts and additional downloaded items are saved.
    Default: D:\visma\Install\Backup

PARAMETER ConfirmLocaleChange
    When present, allows the script to change user/system locale, language list and home location
    to the region specified in the script (default: sv-SE, Sweden).
    It is intentionally an explicit opt-in.

PARAMETER DryRun
    When present, the script will not perform downloads, installer execution, or make system
    changes. It will log actions that would have been performed.

PARAMETER LogFile
    Optional full path to a log file. If not provided the script will create:
      $Destination\install.log

.EXAMPLE
    # Show what would be done for PUF servers (no changes performed)
    .\Run-PreReqServer.ps1 -puf -DryRun

.EXAMPLE
    # Run an all-in-one install and allow locale changes (non-interactive)
    .\Run-PreReqServer.ps1 -AllInOne -ConfirmLocaleChange

.EXAMPLE
    # Run only Visual Integration/Web installs and write log to custom file
    .\Run-PreReqServer.ps1 -viw -LogFile "C:\temp\visma_install.log"

.AUTHOR
    Maintainer: DambergC
    Repository: https://github.com/DambergC/Run-ServerPreReq

.LASTMODIFIED
    2025-10-24

.LICENSE
    Please refer to repository license for terms (if present).

#>


Param(
    [switch]$viw,
    [switch]$batch,
    [switch]$puf,
    [switch]$AllInOne,

    [string]$Destination = "D:\visma\Install\Serverdownloads",
    [string]$BackupFolder = "D:\visma\Install\Backup",
    [switch]$ConfirmLocaleChange,   # Require explicit opt-in to change system locale/settings
    [switch]$DryRun,                # If set, downloads/install commands are shown but not executed
    [string]$LogFile                 # If not set, defaults to $Destination\install.log (created later)
)

# Ensure TLS 1.2 is enabled for download operations
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor `
    [Net.SecurityProtocolType]::Tls11 -bor `
    [Net.SecurityProtocolType]::Tls

# Logging helper
if (-not $LogFile) { $LogFile = Join-Path -Path $Destination -ChildPath 'install.log' }

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','DEBUG')] [string]$Level = 'INFO'
    )
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'WARN'    { Write-Host $line -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
        'DEBUG'   { Write-Host $line -ForegroundColor magenta }
        default   { Write-Host $line }
    }
    try {
        $dir = Split-Path -Path $LogFile -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogFile -Value $line
    } catch {
        Write-Host "Failed to write to log file $LogFile $_" -ForegroundColor Red
    }
}

# Elevation check
function Assert-Elevated {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Log "This script must be run as Administrator. Exiting." "ERROR"
        throw "Administrator privileges required."
    }
}
# Only assert elevation for operations that require it. We run check now because the script will create groups and change system settings.
try { Assert-Elevated } catch { exit 1 }

# Normalize/validate selection
$ModesSelected = @()
if ($viw)   { $ModesSelected += 'viw' }
if ($batch) { $ModesSelected += 'batch' }
if ($puf)   { $ModesSelected += 'puf' }
if ($AllInOne) { $ModesSelected += 'allinone' }

# Validate that exactly one mode is chosen. -AllInOne is a separate, mutually exclusive selection.
if ($ModesSelected.Count -gt 1) {
    Write-Log "Specify exactly one of -viw, -batch, -puf, or -AllInOne. Conflicting selections detected." "ERROR"
    exit 1
}

if ($AllInOne.IsPresent -and ($viw -or $batch -or $puf)) {
    Write-Log "Do not combine -AllInOne with -viw, -batch or -puf. Choose one option only." "ERROR"
    exit 1
}

$RunVIW   = $ModesSelected -contains 'viw'
$RunBatch = $ModesSelected -contains 'batch'
$RunPUF   = $ModesSelected -contains 'puf'
$RunAll   = $ModesSelected -contains 'allinone'

if ($ModesSelected.Count -eq 0) {
    Write-Log "No mode selected. Use -viw, -batch, -puf or -AllInOne. Default behavior will run common tasks only." "WARN"
} else {
    Write-Log "Selected mode: $($ModesSelected -join ', ')" "INFO"
}

# Define download links (original)
$links = @{
    'x86' = 'https://aka.ms/vs/17/release/vc_redist.x86.exe'
    'x64' = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'
}
$redirectUrl = 'https://go.microsoft.com/fwlink/?linkid=2266337'   # ODBC Driver 17
$dotNetUrl = 'https://go.microsoft.com/fwlink/?linkid=2085155'    # .NET 4.8 offline/web redirect
$oleDbUrl = 'https://go.microsoft.com/fwlink/?linkid=2218891'     # OLE DB Driver 18 x64
$aspNetCoreUrl = 'https://builds.dotnet.microsoft.com/dotnet/aspnetcore/Runtime/8.0.21/dotnet-hosting-8.0.21-win.exe'

# System locale settings
$culture = Get-Culture
$WinSystemLocale = Get-WinSystemLocale
$Winuserlanguagelist = Get-WinUserLanguageList
$Winhomelocation = Get-WinHomeLocation

$regionLanguage = 'sv-SE'  # Swedish (Sweden)
$Winhomelocationdefault = 221  # Sweden numeric geoid (as int)

# Ensure destination and backup directories exist
try {
    if (-not (Test-Path $Destination)) {
        Write-Log "Creating destination folder: $Destination" "INFO"
        if (-not $DryRun) { New-Item -ItemType Directory -Path $Destination -Force | Out-Null }
    } else {
        Write-Log "Destination folder exists: $Destination" "DEBUG"
    }
} catch {
    Write-Log "Unable to create or access destination folder '$Destination': $_" "ERROR"
    exit 1
}
try {
    if (-not (Test-Path $BackupFolder)) {
        Write-Log "Creating backup folder: $BackupFolder" "INFO"
        if (-not $DryRun) { New-Item -ItemType Directory -Path $BackupFolder -Force | Out-Null }
    } else {
        Write-Log "Backup folder exists: $BackupFolder" "DEBUG"
    }
} catch {
    Write-Log "Unable to create or access backup folder '$BackupFolder': $_" "ERROR"
    exit 1
}

# Ensure local group exists and add current user
$groupName = "Visma Services Trusted Users"
$currentUser = "$($env:USERDNSDOMAIN)\$($env:USERNAME)"

try {
    if (-not (Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue)) {
        Write-Log "Local group '$groupName' does not exist. Creating..." "INFO"
        if (-not $DryRun) { New-LocalGroup -Name $groupName -Verbose | Out-Null }
    } else {
        Write-Log "Local group '$groupName' exists." "DEBUG"
    }

    # Add current user if not a member
    $groupMembers = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue
    $isAlreadyMember = $groupMembers | Where-Object {
        $_.Name -eq $currentUser -or $_.Name -eq $env:USERNAME -or $_.Name -like "*\$($env:USERNAME)"
    }
    if ($isAlreadyMember) {
        Write-Log "User '$currentUser' is already a member of '$groupName'." "SUCCESS"
    } else {
        Write-Log "Adding '$currentUser' to '$groupName'." "INFO"
        if (-not $DryRun) {
            try {
                Add-LocalGroupMember -Member $currentUser -Group $groupName -Verbose
                Write-Log "Successfully added user to the group." "SUCCESS"
            } catch {
                Write-Log "Add-LocalGroupMember failed: $($_.Exception.Message)" "WARN"
            }
        }
    }
} catch {
    Write-Log "Failed to manage group membership: $($_.Exception.Message)" "WARN"
}

# Download helper that optionally verifies Authenticode signature
function Download-File {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [switch]$VerifySignature
    )

    Write-Log "Downloading: $Url" "INFO"
    Write-Log "Saving to: $OutFile" "DEBUG"

    if ($DryRun) {
        Write-Log "[DryRun] Would download $Url to $OutFile" "INFO"
        return $true
    }

    try {
        # Use Invoke-WebRequest first
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -Headers @{ 'User-Agent' = 'PowerShell' } -TimeoutSec 600 -ErrorAction Stop
        Write-Log "Download finished: $OutFile" "SUCCESS"
    } catch {
        Write-Log "Invoke-WebRequest failed: $($_.Exception.Message). Attempting BITS..." "WARN"
        try {
            Start-BitsTransfer -Source $Url -Destination $OutFile -ErrorAction Stop
            Write-Log "Download finished via BITS: $OutFile" "SUCCESS"
        } catch {
            Write-Log "Both download methods failed: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }

    if ($VerifySignature) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $OutFile -ErrorAction Stop
            if ($sig.Status -eq 'Valid') {
                Write-Log "Authenticode signature is valid for $OutFile" "SUCCESS"
            } else {
                Write-Log "Authenticode signature status for $OutFile $($sig.Status) - $($sig.StatusMessage)" "WARN"
            }
        } catch {
            Write-Log "Could not verify Authenticode signature for $OutFile $_" "WARN"
        }
    }
    return $true
}

# =========================
# Detection & install helpers
# =========================

function Ensure-PersonecPRegFixDownloaded {
    <#
    Ensures PersonecPRegFix.exe is downloaded to a destination path.
    - Does NOT run the executable.
    - Does NOT verify Authenticode signature.
    - Respects $Destination and $DryRun if they exist in the calling script; you can pass a custom OutFile.
    Returns: $true on success (file present and non-zero size), $false on failure.
    #>
    param(
        [string]$Url = 'https://github.com/DambergC/Run-ServerPreReq/releases/latest/download/PersonecPRegFix.exe',
        [string]$OutFile = (Join-Path $Destination 'PersonecPRegFix.exe')
    )

    if (-not $OutFile) { throw "OutFile must be provided or \$Destination must be set in scope." }

    Write-Log "Ensuring PersonecPRegFix is present at $OutFile" "INFO"

    # If file already exists and is non-zero, consider it downloaded
    if (Test-Path $OutFile) {
        try {
            $fi = Get-Item $OutFile -ErrorAction Stop
            if ($fi.Length -gt 0) {
                Write-Log "PersonecPRegFix already downloaded: $OutFile (size: $($fi.Length) bytes)" "SUCCESS"
                return $true
            } else {
                Write-Log "Existing file is zero bytes; will re-download." "WARN"
                Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Log "Unable to inspect existing file $OutFile $_" "WARN"
        }
    }

    if ($DryRun) {
        Write-Log "[DryRun] Would download $Url to $OutFile" "INFO"
        return $true
    }

    # Prefer existing Download-File helper if available (without signature verification)
    if (Get-Command -Name Download-File -ErrorAction SilentlyContinue) {
        if (-not (Download-File -Url $Url -OutFile $OutFile)) {
            Write-Log "Download-File helper failed to download PersonecPRegFix." "ERROR"
            return $false
        }
    } else {
        # Fallback to Invoke-WebRequest then BITS
        Write-Log "Downloading via Invoke-WebRequest: $Url" "INFO"
        try {
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -Headers @{ 'User-Agent' = 'PowerShell' } -TimeoutSec 600 -ErrorAction Stop
            Write-Log "Download finished: $OutFile" "SUCCESS"
        } catch {
            Write-Log "Invoke-WebRequest failed: $($_.Exception.Message). Trying BITS..." "WARN"
            try {
                Start-BitsTransfer -Source $Url -Destination $OutFile -ErrorAction Stop
                Write-Log "Download finished via BITS: $OutFile" "SUCCESS"
            } catch {
                Write-Log "Both download methods failed: $($_.Exception.Message)" "ERROR"
                return $false
            }
        }
    }

    # Confirm file exists and is non-zero
    try {
        $fi = Get-Item $OutFile -ErrorAction Stop
        if ($fi.Length -le 0) {
            Write-Log "Downloaded file is zero bytes: $OutFile" "ERROR"
            return $false
        } else {
            Write-Log "PersonecPRegFix download confirmed: $OutFile (size: $($fi.Length) bytes)" "SUCCESS"
            return $true
        }
    } catch {
        Write-Log "Downloaded file not present after download: $_" "ERROR"
        return $false
    }
}

# Example usage:
# Ensure-PersonecPRegFixDownloaded -OutFile "C:\Temp\PersonecPRegFix.exe"
# or rely on the script's $Destination variable:
Ensure-PersonecPRegFixDownloaded


function Get-NetFxRelease {
    $regPath = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
    $props = Get-ItemProperty -Path $regPath -Name Release -ErrorAction SilentlyContinue

    if (-not $props -or -not $props.Release) {
        return @{ Release = $null; FriendlyVersion = 'Not installed or unknown' }
    }

    $release = [int]$props.Release
    switch ($release) {
        { $_ -ge 528040 } { $ver = '4.8 or later'; break }
        { $_ -ge 461808 } { $ver = '4.7.2'; break }
        { $_ -ge 461308 } { $ver = '4.7.1'; break }
        { $_ -ge 460798 } { $ver = '4.7'; break }
        default { $ver = "Unknown (Release=$release)" }
    }

    return @{ Release = $release; FriendlyVersion = $ver }
}
function Test-NetFx48Installed {
    $info = Get-NetFxRelease
    if ($null -eq $info.Release) { return $false }
    return ($info.Release -ge 528040)
}


function Test-AspNetCore8Installed {
    <#
    Very small, no-switch function.
    Returns $true if any folder under common shared-framework locations starts with "8." (e.g. 8.0.21).
    Usage:
      . .\Test-AspNetCore8Installed.ps1   # dot-source to load the function
      Test-AspNetCore8Installed
    #>

    $dirsToCheck = @()
    if ($env:DOTNET_ROOT) { $dirsToCheck += Join-Path $env:DOTNET_ROOT "shared\Microsoft.AspNetCore.App" }
    if ($env:ProgramFiles)   { $dirsToCheck += Join-Path $env:ProgramFiles   "dotnet\shared\Microsoft.AspNetCore.App" }
    if (${env:ProgramFiles(x86)}) { $dirsToCheck += Join-Path ${env:ProgramFiles(x86)} "dotnet\shared\Microsoft.AspNetCore.App" }
    if ($env:USERPROFILE)   { $dirsToCheck += Join-Path $env:USERPROFILE   ".dotnet\shared\Microsoft.AspNetCore.App" }
    $dirsToCheck += "/usr/share/dotnet/shared/Microsoft.AspNetCore.App"
    $dirsToCheck += "/usr/local/share/dotnet/shared/Microsoft.AspNetCore.App"

    foreach ($d in $dirsToCheck) {
        if (-not $d) { continue }
        try {
            if (Test-Path -LiteralPath $d) {
                $children = Get-ChildItem -LiteralPath $d -Directory -ErrorAction SilentlyContinue
                foreach ($c in $children) {
                    if ($c.Name -like '8.*') { return $true }
                }
            }
        } catch {
            # ignore and continue
        }
    }

    return $false
}


function Test-VisualCRedistributableInstalled {
    param(
        [string]$DisplayNamePattern = 'Visual C\+\+|vcredist|vc_redist|Redistributable|Visual C Runtime',
        [ValidateSet('any','x86','x64')] [string]$Architecture = 'any',
        [string[]]$DllNames = @('msvcp140.dll','vcruntime140.dll','msvcr120.dll','msvcp120.dll','msvcr110.dll','msvcp110.dll'),
        [switch]$CheckDlls
    )
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $matches = foreach ($p in $regPaths) {
        Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and ($_.DisplayName -match $DisplayNamePattern) } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, UninstallString, PSPath,
            @{Name='Architecture';Expression={
                if ($_.PSPath -match 'WOW6432Node') { 'x86' }
                elseif ($_.DisplayName -match '\(x86\)') { 'x86' }
                elseif ($_.DisplayName -match '\(x64\)') { 'x64' }
                else { 'unknown' }
            }}
    }

    if ($Architecture -ne 'any') {
        $matches = $matches | Where-Object { $_.Architecture -eq $Architecture }
    }

    $foundInRegistry = ($matches.Count -gt 0)

    $dllResults = @()
    if ($CheckDlls) {
        $folders = @("$env:windir\System32", "$env:windir\SysWOW64")
        foreach ($f in $folders) {
            foreach ($d in $DllNames) {
                $path = Join-Path $f $d
                $dllResults += [PSCustomObject]@{
                    Folder = $f
                    Dll    = $d
                    Path   = $path
                    Exists = Test-Path $path
                }
            }
        }
    }

    $dllsFound = if ($dllResults) { $dllResults | Where-Object { $_.Exists } } else { @() }
    $foundDllAny = ($dllsFound.Count -gt 0)
    $isInstalled = $foundInRegistry -or $foundDllAny

    return [PSCustomObject]@{
        FoundInRegistry = $foundInRegistry
        RegistryMatches = $matches
        CheckedDlls     = $CheckDlls.IsPresent
        DllsChecked     = $dllResults
        DllsFound       = $dllsFound
        IsInstalled     = $isInstalled
    }
}

function Test-OdbcDriver17Installed {
    $driverName = 'ODBC Driver 17 for SQL Server'
    $driverListPaths = @(
        'HKLM:\SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers',
        'HKLM:\SOFTWARE\Wow6432Node\ODBC\ODBCINST.INI\ODBC Drivers'
    )
    foreach ($p in $driverListPaths) {
        try {
            $props = Get-ItemProperty -Path $p -ErrorAction Stop
        } catch {
            continue
        }
        if ($props -and ($props.PSObject.Properties.Name -contains $driverName)) {
            $val = $props.$driverName
            if ($val -and $val -ne '0') { return $true }
        }
    }
    $specificPaths = @(
        'HKLM:\SOFTWARE\ODBC\ODBCINST.INI\ODBC Driver 17 for SQL Server',
        'HKLM:\SOFTWARE\Wow6432Node\ODBC\ODBCINST.INI\ODBC Driver 17 for SQL Server'
    )
    foreach ($p in $specificPaths) {
        if (Test-Path $p) {
            try {
                $props = Get-ItemProperty -Path $p -ErrorAction Stop
                if ($props.Driver -or $props.Setup) { return $true }
            } catch {
                continue
            }
        }
    }
    return $false
}



function Test-OleDbDriver18Installed {
    <#
    Checks:
    - Search Uninstall registry entries for display names that match "OLE DB Driver" and parse version >= 18.6.5
    - Search common Program Files paths for msoledbsql.dll and inspect file version
    - Returns $true if a matching provider with version >= 18.6.5 is found
    #>

    $targetVersion = [Version]"18.6.5"
    $found = $false
    $correctVersion = $false

    # Check uninstall registry entries (64 and 32-bit)
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($p in $uninstallPaths) {
        $entries = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and ($_.DisplayName -match 'OLE DB Driver') }
        foreach ($entry in $entries) {
            $found = $true
            if ($entry.DisplayVersion) {
                try {
                    $ver = [Version]$entry.DisplayVersion
                    if ($ver -ge $targetVersion) {
                        $correctVersion = $true
                        break
                    }
                } catch {
                    # ignore parse errors and continue
                    continue
                }
            } else {
                # If no DisplayVersion, try to locate a DLL referenced in UninstallString or InstallLocation
                $possiblePaths = @()
                if ($entry.InstallLocation) { $possiblePaths += $entry.InstallLocation }
                if ($entry.UninstallString) { $possiblePaths += $entry.UninstallString }
                foreach ($pp in $possiblePaths) {
                    # Try to find msoledbsql.dll nearby
                    try {
                        $expanded = $pp -replace '"',''
                        $parent = Split-Path -Path $expanded -Parent
                        if ($parent -and (Test-Path $parent)) {
                            $dll = Join-Path $parent 'msoledbsql.dll'
                            if (Test-Path $dll) {
                                try {
                                    $fv = (Get-Item $dll).VersionInfo.FileVersion
                                    $fvv = [Version]$fv
                                    if ($fvv -ge $targetVersion) {
                                        $correctVersion = $true
                                        break
                                    }
                                } catch { continue }
                            }
                        }
                    } catch { continue }
                }
                if ($correctVersion) { break }
            }
        }
        if ($correctVersion) { break }
    }

    # If uninstall registry didn't find the required version, search common Program Files for the DLL
    if (-not $correctVersion) {
        $searchRoots = @($env:ProgramFiles, '$env:ProgramFiles(x86)', "$env:windir\System32", "$env:windir\SysWOW64") | Where-Object { $_ }
        foreach ($root in $searchRoots) {
            try {
                $dlls = Get-ChildItem -Path $root -Filter 'msoledbsql.dll' -Recurse -ErrorAction SilentlyContinue -Force
                foreach ($d in $dlls) {
                    try {
                        $fv = $d.VersionInfo.FileVersion
                        $fvv = [Version]$fv
                        if ($fvv -ge $targetVersion) {
                            $found = $true
                            $correctVersion = $true
                            break
                        }
                    } catch { continue }
                }
                if ($correctVersion) { break }
            } catch { continue }
        }
    }

    return ($found -and $correctVersion)
}

# Install functions updated to respect DryRun and signature checks
function Install-NetFramework48 {
    Write-Log "Checking .NET Framework 4.8..." "INFO"
    if (Test-NetFx48Installed) {
        Write-Log ".NET Framework 4.8 or later already installed." "SUCCESS"
        return
    }
    Write-Log ".NET Framework 4.8 not detected. Preparing to download and install..." "WARN"

    $dotNetExe = Join-Path $Destination 'ndp48-installer.exe'
    if (-not (Download-File -Url $dotNetUrl -OutFile $dotNetExe -VerifySignature)) {
        Write-Log "Failed to download .NET installer." "ERROR"
        return
    }

    if ($DryRun) { Write-Log "[DryRun] Would run: $dotNetExe /q /norestart" "INFO"; return }

    try {
        $installArgs = '/q /norestart'
        $proc = Start-Process -FilePath $dotNetExe -ArgumentList $installArgs -Wait -PassThru
        if ($proc.ExitCode -eq 0) { Write-Log ".NET Framework 4.8 installation completed successfully." "SUCCESS" }
        elseif ($proc.ExitCode -eq 3010) { Write-Log ".NET Framework 4.8 installed; restart required." "WARN" }
        else { Write-Log ".NET installer exited with code $($proc.ExitCode)" "WARN" }
    } catch {
        Write-Log "Error running .NET installer: $_" "ERROR"
    }
    # NOTE: Installers are intentionally retained in $Destination (no automatic deletion)
}

function Install-AspNetCore8 {
    Write-Log "Checking ASP.NET Core 8 installation..." "INFO"


    if (Test-AspNetCore8Installed) {
        Write-Log "ASP.NET Core 8 is already installed." "SUCCESS"

        return
    }
    Write-Log "ASP.NET Core 8 not detected. Preparing to download and install..." "WARN"

    $aspNetCoreExe = Join-Path $Destination 'dotnet-hosting-aspnetcore8.exe'
    if (-not (Download-File -Url $aspNetCoreUrl -OutFile $aspNetCoreExe -VerifySignature)) {
        Write-Log "Failed to download ASP.NET Core 8 installer." "ERROR"
        return
    }

    if ($DryRun) {
        Write-Log "[DryRun] Would run: $aspNetCoreExe /quiet /norestart" "INFO"
        return
    }

    try {
        $installArgs = '/quiet /norestart'
        $proc = Start-Process -FilePath $aspNetCoreExe -ArgumentList $installArgs -Wait -PassThru
        if ($proc.ExitCode -eq 0) {
            Write-Log "ASP.NET Core 8 installation completed successfully." "SUCCESS"
        } elseif ($proc.ExitCode -eq 3010) {
            Write-Log "ASP.NET Core 8 installed; restart required." "WARN"
        } else {
            Write-Log "ASP.NET Core installer exited with code $($proc.ExitCode)" "WARN"
        }
    } catch {
        Write-Log "Error running ASP.NET Core installer: $_" "ERROR"
    }
    # NOTE: Installer left in $Destination for later reuse
}
function Install-VisualCRedistributable {
    Write-Log "Checking Visual C++ Redistributables..." "INFO"
    $vcplusplusinstalled = Test-VisualCRedistributableInstalled
    if ($vcplusplusinstalled.IsInstalled) {
        Write-Log "Visual C++ Redistributable is installed." "SUCCESS"
        return
    }
    Write-Log "Visual C++ Redistributable not detected. Preparing to download and install..." "WARN"

    foreach ($arch in $links.Keys) {
        $url = $links[$arch]
        $outfile = Join-Path $Destination "vc_redist.$arch.exe"
        if (-not (Download-File -Url $url -OutFile $outfile -VerifySignature)) {
            Write-Log "Failed to download Visual C++ redistributable for $arch" "ERROR"
            continue
        }
        if ($DryRun) { Write-Log "[DryRun] Would run: $outfile /install /quiet /norestart" "INFO"; continue }
        try {
            $installArgs = "/install /quiet /norestart"
            $process = Start-Process -FilePath $outfile -ArgumentList $installArgs -Wait -PassThru
            if ($process.ExitCode -eq 0) { Write-Log "Visual C++ ($arch) installed successfully." "SUCCESS" }
            elseif ($process.ExitCode -eq 3010) { Write-Log "Visual C++ ($arch) installed; restart required." "WARN" }
            elseif ($process.ExitCode -eq 1638) { Write-Log "Visual C++ ($arch) already present or newer exists." "WARN" }
            else { Write-Log "Visual C++ ($arch) installer exit code $($process.ExitCode)" "WARN" }
        } catch {
            Write-Log "Failed to run Visual C++ installer for $arch $_" "ERROR"
        }
        # NOTE: Do not delete $outfile - keep installers in $Destination
    }
}

function Install-OdbcDriver17 {
    Write-Log "Checking Microsoft ODBC Driver 17..." "INFO"
    if (Test-OdbcDriver17Installed) {
        Write-Log "ODBC Driver 17 is already installed." "SUCCESS"
        return
    }
    Write-Log "ODBC Driver 17 not detected. Preparing to download and install..." "WARN"
    $outFile = Join-Path $Destination 'msodbcsql17.x64.msi'
    if (-not (Download-File -Url $redirectUrl -OutFile $outFile -VerifySignature)) {
        Write-Log "Failed to download ODBC Driver 17." "ERROR"
        return
    }
    if ($DryRun) { Write-Log "[DryRun] Would run: msiexec.exe /i `"$outFile`" /qb IACCEPTMSODBCSQLLICENSETERMS=YES ALLUSERS=1 /norestart" "INFO"; return }
    try {
        $installArgs = "/i `"$outFile`" /qb IACCEPTMSODBCSQLLICENSETERMS=YES ALLUSERS=1 /norestart"
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru
        if ($process.ExitCode -eq 0) { Write-Log "ODBC Driver 17 installed successfully." "SUCCESS" }
        elseif ($process.ExitCode -eq 3010) { Write-Log "ODBC Driver 17 installed; restart required." "WARN" }
        else { Write-Log "ODBC Driver 17 installer exit code $($process.ExitCode)" "WARN" }
    } catch {
        Write-Log "Failed to run msiexec for ODBC Driver 17: $_" "ERROR"
    }
    # NOTE: MSI is kept in $Destination for future use
}

function Install-OleDbDriver18 {
    Write-Log "Checking Microsoft OLE DB Driver 18..." "INFO"
    if (Test-OleDbDriver18Installed) {
        Write-Log "OLE DB Driver 18.6.5+ is already installed." "SUCCESS"
        return
    }
    Write-Log "OLE DB Driver 18.6.5+ not found. Preparing to download and install..." "WARN"
    $oleDbMsi = Join-Path $Destination 'msoledbsql.msi'
    if (-not (Download-File -Url $oleDbUrl -OutFile $oleDbMsi -VerifySignature)) {
        Write-Log "Failed to download OLE DB Driver installer." "ERROR"
        return
    }
    if ($DryRun) { Write-Log "[DryRun] Would run: msiexec.exe /i `"$oleDbMsi`" /quiet /norestart IACCEPTMSOLEDBSQLLICENSETERMS=YES" "INFO"; return }
    try {
        $installArgs = "/i `"$oleDbMsi`" /quiet /norestart IACCEPTMSOLEDBSQLLICENSETERMS=YES"
        $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $installArgs -Wait -PassThru
        if ($proc.ExitCode -eq 0) { Write-Log "OLE DB Driver 18 installed successfully." "SUCCESS" }
        elseif ($proc.ExitCode -eq 3010) { Write-Log "OLE DB Driver 18 installed; restart may be required." "WARN" }
        else { Write-Log "OLE DB installer exit code $($proc.ExitCode)" "WARN" }
    } catch {
        Write-Log "Failed to run OLE DB installer: $_" "ERROR"
    }
    # NOTE: MSI is intentionally kept in $Destination
}

# Region language configuration section.
Write-Log "Starting region language configuration..." "INFO"

if (-not $ConfirmLocaleChange) {
    Write-Log "Locale/system language change is disabled by default. Use -ConfirmLocaleChange to allow changes." "WARN"
} else {
    # Only proceed if user specifically confirmed
    try {
        if ($culture.Name -ne $regionLanguage) {
            Write-Log "User culture ($($culture.Name)) does not match target ($regionLanguage). Setting culture." "WARN"
            if (-not $DryRun) { Set-Culture $regionLanguage }
            Write-Log "User culture set to $regionLanguage." "SUCCESS"
        } else { Write-Log "User culture already $regionLanguage." "DEBUG" }

        if ($WinSystemLocale.Name -ne $regionLanguage) {
            Write-Log "System locale ($($WinSystemLocale.Name)) does not match target ($regionLanguage). Setting system locale." "WARN"
            if (-not $DryRun) { Set-WinSystemLocale $regionLanguage }
            Write-Log "System locale set to $regionLanguage." "SUCCESS"
        } else { Write-Log "System locale already $regionLanguage." "DEBUG" }

        if (-not ($Winuserlanguagelist.LanguageTag -contains $regionLanguage)) {
            Write-Log "User language list does not contain $regionLanguage. Adding..." "WARN"
            if (-not $DryRun) {
                $newLang = New-WinUserLanguageList $regionLanguage
                Set-WinUserLanguageList -LanguageList $newLang -Force
            }
            Write-Log "User language list updated to include $regionLanguage." "SUCCESS"
        } else { Write-Log "User language list already contains $regionLanguage." "DEBUG" }

        if ($Winhomelocation.GeoId -ne $Winhomelocationdefault) {
            Write-Log "Home location geoid ($($Winhomelocation.GeoId)) does not match target ($Winhomelocationdefault). Setting home location." "WARN"
            if (-not $DryRun) { Set-WinHomeLocation -GeoId $Winhomelocationdefault }
            Write-Log "Home location set to $Winhomelocationdefault." "SUCCESS"
        } else { Write-Log "Home location geoid already $Winhomelocationdefault." "DEBUG" }

        if (-not $DryRun) {
            Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true
            Write-Log "Copied user international settings to system and new user profiles." "SUCCESS"
        } else {
            Write-Log "[DryRun] Would copy user international settings to system and new user profiles." "INFO"
        }
    } catch {
        Write-Log "Locale configuration error: $_" "ERROR"
    }
}

# Download a backup script if missing
$cygateBackup = Join-Path $BackupFolder 'CygateScript.ps1'
if (Test-Path $cygateBackup) {
    Write-Log "CygateScript.ps1 already exists in Backup folder, skipping download." "INFO"
} else {
    Write-Log "CygateScript.ps1 missing in Backup folder; downloading..." "INFO"
    $cygateUrl = 'https://github.com/Dambergc/Vismascript/releases/latest/download/CygateScript.ps1'
    if (-not (Download-File -Url $cygateUrl -OutFile $cygateBackup -VerifySignature)) {
        Write-Log "Failed to download CygateScript.ps1" "WARN"
    }
}

# Run installs according to selected modes
if ($RunAll) {
    Install-NetFramework48
    Install-AspNetCore8
    Install-OleDbDriver18
    Install-VisualCRedistributable
    Install-OdbcDriver17
}

if ($RunVIW) {
    Install-NetFramework48
}
if ($RunPUF) {
    Install-NetFramework48
    Install-AspNetCore8
    Install-OleDbDriver18
    Install-VisualCRedistributable
    Install-OdbcDriver17
}
if ($RunBatch) {
    Install-NetFramework48
    Install-AspNetCore8
    Install-OleDbDriver18
    Install-VisualCRedistributable
    Install-OdbcDriver17
}


Write-Log "Installation script completed. Check log file at $LogFile for details." "INFO"
Write-Log "If installations ran, please restart the computer for all changes to take effect (if required)." "WARN"
      - Microsoft OLE DB Driver 18 (with version check)

    The script supports modes to install only relevant components for different server
    types (viw, batch, puf) or an all-in-one mode.

.NOTES
    - This script must be run as Administrator (the script checks for elevation).
    - By default locale changes are disabled; use -ConfirmLocaleChange to opt in.
    - Use -DryRun to show actions without executing downloads or installers.
    - The script writes logs to $Destination\install.log by default (can be overridden with -LogFile).

PARAMETER viw
    Select Visual Integration/Web (VIW) server prereqs only.

PARAMETER batch
    Select Batch server prereqs only.

PARAMETER puf
    Select PUF server prereqs only.

PARAMETER AllInOne
    Shortcut to run viw, batch and puf installs (equivalent to -viw -batch -puf).
    Note: Do not combine -AllInOne with any of -viw, -batch or -puf.

PARAMETER Destination
    Path where installers and temporary downloads will be stored.
    Default: D:\visma\Install\Serverdownloads

PARAMETER BackupFolder
    Path where backup scripts and additional downloaded items are saved.
    Default: D:\visma\Install\Backup

PARAMETER ConfirmLocaleChange
    When present, allows the script to change user/system locale, language list and home location
    to the region specified in the script (default: sv-SE, Sweden).
    It is intentionally an explicit opt-in.

PARAMETER DryRun
    When present, the script will not perform downloads, installer execution, or make system
    changes. It will log actions that would have been performed.

PARAMETER LogFile
    Optional full path to a log file. If not provided the script will create:
      $Destination\install.log

.EXAMPLE
    # Show what would be done for PUF servers (no changes performed)
    .\Run-PreReqServer.ps1 -puf -DryRun

.EXAMPLE
    # Run an all-in-one install and allow locale changes (non-interactive)
    .\Run-PreReqServer.ps1 -AllInOne -ConfirmLocaleChange

.EXAMPLE
    # Run only Visual Integration/Web installs and write log to custom file
    .\Run-PreReqServer.ps1 -viw -LogFile "C:\temp\visma_install.log"

.AUTHOR
    Maintainer: DambergC
    Repository: https://github.com/DambergC/Run-ServerPreReq

.LASTMODIFIED
    2025-10-24

.LICENSE
    Please refer to repository license for terms (if present).

#>


Param(
    [switch]$viw,
    [switch]$batch,
    [switch]$puf,
    [switch]$AllInOne,

    [string]$Destination = "D:\visma\Install\Serverdownloads",
    [string]$BackupFolder = "D:\visma\Install\Backup",
    [switch]$ConfirmLocaleChange,   # Require explicit opt-in to change system locale/settings
    [switch]$DryRun,                # If set, downloads/install commands are shown but not executed
    [string]$LogFile                 # If not set, defaults to $Destination\install.log (created later)
)

# Ensure TLS 1.2 is enabled for download operations
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor `
    [Net.SecurityProtocolType]::Tls11 -bor `
    [Net.SecurityProtocolType]::Tls

# Logging helper
if (-not $LogFile) { $LogFile = Join-Path -Path $Destination -ChildPath 'install.log' }

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','DEBUG')] [string]$Level = 'INFO'
    )
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'WARN'    { Write-Host $line -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
        'DEBUG'   { Write-Host $line -ForegroundColor magenta }
        default   { Write-Host $line }
    }
    try {
        $dir = Split-Path -Path $LogFile -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Add-Content -Path $LogFile -Value $line
    } catch {
        Write-Host "Failed to write to log file $LogFile $_" -ForegroundColor Red
    }
}

# Elevation check
function Assert-Elevated {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Log "This script must be run as Administrator. Exiting." "ERROR"
        throw "Administrator privileges required."
    }
}
# Only assert elevation for operations that require it. We run check now because the script will create groups and change system settings.
try { Assert-Elevated } catch { exit 1 }

# Normalize/validate selection
$ModesSelected = @()
if ($viw)   { $ModesSelected += 'viw' }
if ($batch) { $ModesSelected += 'batch' }
if ($puf)   { $ModesSelected += 'puf' }
if ($AllInOne) { $ModesSelected = @('viw','batch','puf') }

if (($AllInOne -and ($viw -or $batch -or $puf)) -or (($ModesSelected.Count -gt 1) -and -not $AllInOne)) {
    Write-Log "Specify exactly one of -viw, -batch, -puf, or use -AllInOne. Conflicting selections detected." "ERROR"
    exit 1
}

$RunVIW   = $ModesSelected -contains 'viw'
$RunBatch = $ModesSelected -contains 'batch'
$RunPUF   = $ModesSelected -contains 'puf'
$RunAll   = $AllInOne.IsPresent

if ($ModesSelected.Count -eq 0) {
    Write-Log "No mode selected. Use -viw, -batch, -puf or -AllInOne. Default behavior will run common tasks only." "WARN"
} else {
    Write-Log "Selected mode(s): $($ModesSelected -join ', ')" "INFO"
}

# Define download links (original)
$links = @{
    'x86' = 'https://aka.ms/vs/17/release/vc_redist.x86.exe'
    'x64' = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'
}
$redirectUrl = 'https://go.microsoft.com/fwlink/?linkid=2266337'   # ODBC Driver 17
$dotNetUrl = 'https://go.microsoft.com/fwlink/?linkid=2085155'    # .NET 4.8 offline/web redirect
$oleDbUrl = 'https://go.microsoft.com/fwlink/?linkid=2218891'     # OLE DB Driver 18 x64
$aspNetCoreUrl = 'https://builds.dotnet.microsoft.com/dotnet/aspnetcore/Runtime/8.0.21/dotnet-hosting-8.0.21-win.exe'

# System locale settings
$culture = Get-Culture
$WinSystemLocale = Get-WinSystemLocale
$Winuserlanguagelist = Get-WinUserLanguageList
$Winhomelocation = Get-WinHomeLocation

$regionLanguage = 'sv-SE'  # Swedish (Sweden)
$Winhomelocationdefault = 221  # Sweden numeric geoid (as int)

# Ensure destination and backup directories exist
try {
    if (-not (Test-Path $Destination)) {
        Write-Log "Creating destination folder: $Destination" "INFO"
        if (-not $DryRun) { New-Item -ItemType Directory -Path $Destination -Force | Out-Null }
    } else {
        Write-Log "Destination folder exists: $Destination" "DEBUG"
    }
} catch {
    Write-Log "Unable to create or access destination folder '$Destination': $_" "ERROR"
    exit 1
}
try {
    if (-not (Test-Path $BackupFolder)) {
        Write-Log "Creating backup folder: $BackupFolder" "INFO"
        if (-not $DryRun) { New-Item -ItemType Directory -Path $BackupFolder -Force | Out-Null }
    } else {
        Write-Log "Backup folder exists: $BackupFolder" "DEBUG"
    }
} catch {
    Write-Log "Unable to create or access backup folder '$BackupFolder': $_" "ERROR"
    exit 1
}

# Ensure local group exists and add current user
$groupName = "Visma Services Trusted Users"
$currentUser = "$($env:USERDNSDOMAIN)\$($env:USERNAME)"

try {
    if (-not (Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue)) {
        Write-Log "Local group '$groupName' does not exist. Creating..." "INFO"
        if (-not $DryRun) { New-LocalGroup -Name $groupName -Verbose | Out-Null }
    } else {
        Write-Log "Local group '$groupName' exists." "DEBUG"
    }

    # Add current user if not a member
    $groupMembers = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue
    $isAlreadyMember = $groupMembers | Where-Object {
        $_.Name -eq $currentUser -or $_.Name -eq $env:USERNAME -or $_.Name -like "*\$($env:USERNAME)"
    }
    if ($isAlreadyMember) {
        Write-Log "User '$currentUser' is already a member of '$groupName'." "SUCCESS"
    } else {
        Write-Log "Adding '$currentUser' to '$groupName'." "INFO"
        if (-not $DryRun) {
            try {
                Add-LocalGroupMember -Member $currentUser -Group $groupName -Verbose
                Write-Log "Successfully added user to the group." "SUCCESS"
            } catch {
                Write-Log "Add-LocalGroupMember failed: $($_.Exception.Message)" "WARN"
            }
        }
    }
} catch {
    Write-Log "Failed to manage group membership: $($_.Exception.Message)" "WARN"
}

# Download helper that optionally verifies Authenticode signature
function Download-File {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$OutFile,
        [switch]$VerifySignature
    )

    Write-Log "Downloading: $Url" "INFO"
    Write-Log "Saving to: $OutFile" "DEBUG"

    if ($DryRun) {
        Write-Log "[DryRun] Would download $Url to $OutFile" "INFO"
        return $true
    }

    try {
        # Use Invoke-WebRequest first
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -Headers @{ 'User-Agent' = 'PowerShell' } -TimeoutSec 600 -ErrorAction Stop
        Write-Log "Download finished: $OutFile" "SUCCESS"
    } catch {
        Write-Log "Invoke-WebRequest failed: $($_.Exception.Message). Attempting BITS..." "WARN"
        try {
            Start-BitsTransfer -Source $Url -Destination $OutFile -ErrorAction Stop
            Write-Log "Download finished via BITS: $OutFile" "SUCCESS"
        } catch {
            Write-Log "Both download methods failed: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }

    if ($VerifySignature) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $OutFile -ErrorAction Stop
            if ($sig.Status -eq 'Valid') {
                Write-Log "Authenticode signature is valid for $OutFile" "SUCCESS"
            } else {
                Write-Log "Authenticode signature status for $OutFile $($sig.Status) - $($sig.StatusMessage)" "WARN"
            }
        } catch {
            Write-Log "Could not verify Authenticode signature for $OutFile $_" "WARN"
        }
    }
    return $true
}

# =========================
# Detection & install helpers
# =========================

function Ensure-PersonecPRegFixDownloaded {
    <#
    Ensures PersonecPRegFix.exe is downloaded to a destination path.
    - Does NOT run the executable.
    - Does NOT verify Authenticode signature.
    - Respects $Destination and $DryRun if they exist in the calling script; you can pass a custom OutFile.
    Returns: $true on success (file present and non-zero size), $false on failure.
    #>
    param(
        [string]$Url = 'https://github.com/DambergC/Run-ServerPreReq/releases/latest/download/PersonecPRegFix.exe',
        [string]$OutFile = (Join-Path $Destination 'PersonecPRegFix.exe')
    )

    if (-not $OutFile) { throw "OutFile must be provided or \$Destination must be set in scope." }

    Write-Log "Ensuring PersonecPRegFix is present at $OutFile" "INFO"

    # If file already exists and is non-zero, consider it downloaded
    if (Test-Path $OutFile) {
        try {
            $fi = Get-Item $OutFile -ErrorAction Stop
            if ($fi.Length -gt 0) {
                Write-Log "PersonecPRegFix already downloaded: $OutFile (size: $($fi.Length) bytes)" "SUCCESS"
                return $true
            } else {
                Write-Log "Existing file is zero bytes; will re-download." "WARN"
                Remove-Item $OutFile -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Log "Unable to inspect existing file $OutFile $_" "WARN"
        }
    }

    if ($DryRun) {
        Write-Log "[DryRun] Would download $Url to $OutFile" "INFO"
        return $true
    }

    # Prefer existing Download-File helper if available (without signature verification)
    if (Get-Command -Name Download-File -ErrorAction SilentlyContinue) {
        if (-not (Download-File -Url $Url -OutFile $OutFile)) {
            Write-Log "Download-File helper failed to download PersonecPRegFix." "ERROR"
            return $false
        }
    } else {
        # Fallback to Invoke-WebRequest then BITS
        Write-Log "Downloading via Invoke-WebRequest: $Url" "INFO"
        try {
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -Headers @{ 'User-Agent' = 'PowerShell' } -TimeoutSec 600 -ErrorAction Stop
            Write-Log "Download finished: $OutFile" "SUCCESS"
        } catch {
            Write-Log "Invoke-WebRequest failed: $($_.Exception.Message). Trying BITS..." "WARN"
            try {
                Start-BitsTransfer -Source $Url -Destination $OutFile -ErrorAction Stop
                Write-Log "Download finished via BITS: $OutFile" "SUCCESS"
            } catch {
                Write-Log "Both download methods failed: $($_.Exception.Message)" "ERROR"
                return $false
            }
        }
    }

    # Confirm file exists and is non-zero
    try {
        $fi = Get-Item $OutFile -ErrorAction Stop
        if ($fi.Length -le 0) {
            Write-Log "Downloaded file is zero bytes: $OutFile" "ERROR"
            return $false
        } else {
            Write-Log "PersonecPRegFix download confirmed: $OutFile (size: $($fi.Length) bytes)" "SUCCESS"
            return $true
        }
    } catch {
        Write-Log "Downloaded file not present after download: $_" "ERROR"
        return $false
    }
}

# Example usage:
# Ensure-PersonecPRegFixDownloaded -OutFile "C:\Temp\PersonecPRegFix.exe"
# or rely on the script's $Destination variable:
Ensure-PersonecPRegFixDownloaded


function Get-NetFxRelease {
    $regPath = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
    $props = Get-ItemProperty -Path $regPath -Name Release -ErrorAction SilentlyContinue

    if (-not $props -or -not $props.Release) {
        return @{ Release = $null; FriendlyVersion = 'Not installed or unknown' }
    }

    $release = [int]$props.Release
    switch ($release) {
        { $_ -ge 528040 } { $ver = '4.8 or later'; break }
        { $_ -ge 461808 } { $ver = '4.7.2'; break }
        { $_ -ge 461308 } { $ver = '4.7.1'; break }
        { $_ -ge 460798 } { $ver = '4.7'; break }
        default { $ver = "Unknown (Release=$release)" }
    }

    return @{ Release = $release; FriendlyVersion = $ver }
}
function Test-NetFx48Installed {
    $info = Get-NetFxRelease
    if ($null -eq $info.Release) { return $false }
    return ($info.Release -ge 528040)
}


function Test-AspNetCore8Installed {
    <#
    Very small, no-switch function.
    Returns $true if any folder under common shared-framework locations starts with "8." (e.g. 8.0.21).
    Usage:
      . .\Test-AspNetCore8Installed.ps1   # dot-source to load the function
      Test-AspNetCore8Installed
    #>

    $dirsToCheck = @()
    if ($env:DOTNET_ROOT) { $dirsToCheck += Join-Path $env:DOTNET_ROOT "shared\Microsoft.AspNetCore.App" }
    if ($env:ProgramFiles)   { $dirsToCheck += Join-Path $env:ProgramFiles   "dotnet\shared\Microsoft.AspNetCore.App" }
    if (${env:ProgramFiles(x86)}) { $dirsToCheck += Join-Path ${env:ProgramFiles(x86)} "dotnet\shared\Microsoft.AspNetCore.App" }
    if ($env:USERPROFILE)   { $dirsToCheck += Join-Path $env:USERPROFILE   ".dotnet\shared\Microsoft.AspNetCore.App" }
    $dirsToCheck += "/usr/share/dotnet/shared/Microsoft.AspNetCore.App"
    $dirsToCheck += "/usr/local/share/dotnet/shared/Microsoft.AspNetCore.App"

    foreach ($d in $dirsToCheck) {
        if (-not $d) { continue }
        try {
            if (Test-Path -LiteralPath $d) {
                $children = Get-ChildItem -LiteralPath $d -Directory -ErrorAction SilentlyContinue
                foreach ($c in $children) {
                    if ($c.Name -like '8.*') { return $true }
                }
            }
        } catch {
            # ignore and continue
        }
    }

    return $false
}


function Test-VisualCRedistributableInstalled {
    param(
        [string]$DisplayNamePattern = 'Visual C\+\+|vcredist|vc_redist|Redistributable|Visual C Runtime',
        [ValidateSet('any','x86','x64')] [string]$Architecture = 'any',
        [string[]]$DllNames = @('msvcp140.dll','vcruntime140.dll','msvcr120.dll','msvcp120.dll','msvcr110.dll','msvcp110.dll'),
        [switch]$CheckDlls
    )
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $matches = foreach ($p in $regPaths) {
        Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and ($_.DisplayName -match $DisplayNamePattern) } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, UninstallString, PSPath,
            @{Name='Architecture';Expression={
                if ($_.PSPath -match 'WOW6432Node') { 'x86' }
                elseif ($_.DisplayName -match '\(x86\)') { 'x86' }
                elseif ($_.DisplayName -match '\(x64\)') { 'x64' }
                else { 'unknown' }
            }}
    }

    if ($Architecture -ne 'any') {
        $matches = $matches | Where-Object { $_.Architecture -eq $Architecture }
    }

    $foundInRegistry = ($matches.Count -gt 0)

    $dllResults = @()
    if ($CheckDlls) {
        $folders = @("$env:windir\System32", "$env:windir\SysWOW64")
        foreach ($f in $folders) {
            foreach ($d in $DllNames) {
                $path = Join-Path $f $d
                $dllResults += [PSCustomObject]@{
                    Folder = $f
                    Dll    = $d
                    Path   = $path
                    Exists = Test-Path $path
                }
            }
        }
    }

    $dllsFound = if ($dllResults) { $dllResults | Where-Object { $_.Exists } } else { @() }
    $foundDllAny = ($dllsFound.Count -gt 0)
    $isInstalled = $foundInRegistry -or $foundDllAny

    return [PSCustomObject]@{
        FoundInRegistry = $foundInRegistry
        RegistryMatches = $matches
        CheckedDlls     = $CheckDlls.IsPresent
        DllsChecked     = $dllResults
        DllsFound       = $dllsFound
        IsInstalled     = $isInstalled
    }
}

function Test-OdbcDriver17Installed {
    $driverName = 'ODBC Driver 17 for SQL Server'
    $driverListPaths = @(
        'HKLM:\SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers',
        'HKLM:\SOFTWARE\Wow6432Node\ODBC\ODBCINST.INI\ODBC Drivers'
    )
    foreach ($p in $driverListPaths) {
        try {
            $props = Get-ItemProperty -Path $p -ErrorAction Stop
        } catch {
            continue
        }
        if ($props -and ($props.PSObject.Properties.Name -contains $driverName)) {
            $val = $props.$driverName
            if ($val -and $val -ne '0') { return $true }
        }
    }
    $specificPaths = @(
        'HKLM:\SOFTWARE\ODBC\ODBCINST.INI\ODBC Driver 17 for SQL Server',
        'HKLM:\SOFTWARE\Wow6432Node\ODBC\ODBCINST.INI\ODBC Driver 17 for SQL Server'
    )
    foreach ($p in $specificPaths) {
        if (Test-Path $p) {
            try {
                $props = Get-ItemProperty -Path $p -ErrorAction Stop
                if ($props.Driver -or $props.Setup) { return $true }
            } catch {
                continue
            }
        }
    }
    return $false
}



function Test-OleDbDriver18Installed {
    <#
    Checks:
    - Search Uninstall registry entries for display names that match "OLE DB Driver" and parse version >= 18.6.5
    - Search common Program Files paths for msoledbsql.dll and inspect file version
    - Returns $true if a matching provider with version >= 18.6.5 is found
    #>

    $targetVersion = [Version]"18.6.5"
    $found = $false
    $correctVersion = $false

    # Check uninstall registry entries (64 and 32-bit)
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($p in $uninstallPaths) {
        $entries = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and ($_.DisplayName -match 'OLE DB Driver') }
        foreach ($entry in $entries) {
            $found = $true
            if ($entry.DisplayVersion) {
                try {
                    $ver = [Version]$entry.DisplayVersion
                    if ($ver -ge $targetVersion) {
                        $correctVersion = $true
                        break
                    }
                } catch {
                    # ignore parse errors and continue
                    continue
                }
            } else {
                # If no DisplayVersion, try to locate a DLL referenced in UninstallString or InstallLocation
                $possiblePaths = @()
                if ($entry.InstallLocation) { $possiblePaths += $entry.InstallLocation }
                if ($entry.UninstallString) { $possiblePaths += $entry.UninstallString }
                foreach ($pp in $possiblePaths) {
                    # Try to find msoledbsql.dll nearby
                    try {
                        $expanded = $pp -replace '"',''
                        $parent = Split-Path -Path $expanded -Parent
                        if ($parent -and (Test-Path $parent)) {
                            $dll = Join-Path $parent 'msoledbsql.dll'
                            if (Test-Path $dll) {
                                try {
                                    $fv = (Get-Item $dll).VersionInfo.FileVersion
                                    $fvv = [Version]$fv
                                    if ($fvv -ge $targetVersion) {
                                        $correctVersion = $true
                                        break
                                    }
                                } catch { continue }
                            }
                        }
                    } catch { continue }
                }
                if ($correctVersion) { break }
            }
        }
        if ($correctVersion) { break }
    }

    # If uninstall registry didn't find the required version, search common Program Files for the DLL
    if (-not $correctVersion) {
        $searchRoots = @($env:ProgramFiles, '$env:ProgramFiles(x86)', "$env:windir\System32", "$env:windir\SysWOW64") | Where-Object { $_ }
        foreach ($root in $searchRoots) {
            try {
                $dlls = Get-ChildItem -Path $root -Filter 'msoledbsql.dll' -Recurse -ErrorAction SilentlyContinue -Force
                foreach ($d in $dlls) {
                    try {
                        $fv = $d.VersionInfo.FileVersion
                        $fvv = [Version]$fv
                        if ($fvv -ge $targetVersion) {
                            $found = $true
                            $correctVersion = $true
                            break
                        }
                    } catch { continue }
                }
                if ($correctVersion) { break }
            } catch { continue }
        }
    }

    return ($found -and $correctVersion)
}

# Install functions updated to respect DryRun and signature checks
function Install-NetFramework48 {
    Write-Log "Checking .NET Framework 4.8..." "INFO"
    if (Test-NetFx48Installed) {
        Write-Log ".NET Framework 4.8 or later already installed." "SUCCESS"
        return
    }
    Write-Log ".NET Framework 4.8 not detected. Preparing to download and install..." "WARN"

    $dotNetExe = Join-Path $Destination 'ndp48-installer.exe'
    if (-not (Download-File -Url $dotNetUrl -OutFile $dotNetExe -VerifySignature)) {
        Write-Log "Failed to download .NET installer." "ERROR"
        return
    }

    if ($DryRun) { Write-Log "[DryRun] Would run: $dotNetExe /q /norestart" "INFO"; return }

    try {
        $installArgs = '/q /norestart'
        $proc = Start-Process -FilePath $dotNetExe -ArgumentList $installArgs -Wait -PassThru
        if ($proc.ExitCode -eq 0) { Write-Log ".NET Framework 4.8 installation completed successfully." "SUCCESS" }
        elseif ($proc.ExitCode -eq 3010) { Write-Log ".NET Framework 4.8 installed; restart required." "WARN" }
        else { Write-Log ".NET installer exited with code $($proc.ExitCode)" "WARN" }
    } catch {
        Write-Log "Error running .NET installer: $_" "ERROR"
    }
    # NOTE: Installers are intentionally retained in $Destination (no automatic deletion)
}

function Install-AspNetCore8 {
    Write-Log "Checking ASP.NET Core 8 installation..." "INFO"


    if (Test-AspNetCore8Installed) {
        Write-Log "ASP.NET Core 8 is already installed." "SUCCESS"

        return
    }
    Write-Log "ASP.NET Core 8 not detected. Preparing to download and install..." "WARN"

    $aspNetCoreExe = Join-Path $Destination 'dotnet-hosting-aspnetcore8.exe'
    if (-not (Download-File -Url $aspNetCoreUrl -OutFile $aspNetCoreExe -VerifySignature)) {
        Write-Log "Failed to download ASP.NET Core 8 installer." "ERROR"
        return
    }

    if ($DryRun) {
        Write-Log "[DryRun] Would run: $aspNetCoreExe /quiet /norestart" "INFO"
        return
    }

    try {
        $installArgs = '/quiet /norestart'
        $proc = Start-Process -FilePath $aspNetCoreExe -ArgumentList $installArgs -Wait -PassThru
        if ($proc.ExitCode -eq 0) {
            Write-Log "ASP.NET Core 8 installation completed successfully." "SUCCESS"
        } elseif ($proc.ExitCode -eq 3010) {
            Write-Log "ASP.NET Core 8 installed; restart required." "WARN"
        } else {
            Write-Log "ASP.NET Core installer exited with code $($proc.ExitCode)" "WARN"
        }
    } catch {
        Write-Log "Error running ASP.NET Core installer: $_" "ERROR"
    }
    # NOTE: Installer left in $Destination for later reuse
}
function Install-VisualCRedistributable {
    Write-Log "Checking Visual C++ Redistributables..." "INFO"
    $vcplusplusinstalled = Test-VisualCRedistributableInstalled
    if ($vcplusplusinstalled.IsInstalled) {
        Write-Log "Visual C++ Redistributable is installed." "SUCCESS"
        return
    }
    Write-Log "Visual C++ Redistributable not detected. Preparing to download and install..." "WARN"

    foreach ($arch in $links.Keys) {
        $url = $links[$arch]
        $outfile = Join-Path $Destination "vc_redist.$arch.exe"
        if (-not (Download-File -Url $url -OutFile $outfile -VerifySignature)) {
            Write-Log "Failed to download Visual C++ redistributable for $arch" "ERROR"
            continue
        }
        if ($DryRun) { Write-Log "[DryRun] Would run: $outfile /install /quiet /norestart" "INFO"; continue }
        try {
            $installArgs = "/install /quiet /norestart"
            $process = Start-Process -FilePath $outfile -ArgumentList $installArgs -Wait -PassThru
            if ($process.ExitCode -eq 0) { Write-Log "Visual C++ ($arch) installed successfully." "SUCCESS" }
            elseif ($process.ExitCode -eq 3010) { Write-Log "Visual C++ ($arch) installed; restart required." "WARN" }
            elseif ($process.ExitCode -eq 1638) { Write-Log "Visual C++ ($arch) already present or newer exists." "WARN" }
            else { Write-Log "Visual C++ ($arch) installer exit code $($process.ExitCode)" "WARN" }
        } catch {
            Write-Log "Failed to run Visual C++ installer for $arch $_" "ERROR"
        }
        # NOTE: Do not delete $outfile - keep installers in $Destination
    }
}

function Install-OdbcDriver17 {
    Write-Log "Checking Microsoft ODBC Driver 17..." "INFO"
    if (Test-OdbcDriver17Installed) {
        Write-Log "ODBC Driver 17 is already installed." "SUCCESS"
        return
    }
    Write-Log "ODBC Driver 17 not detected. Preparing to download and install..." "WARN"
    $outFile = Join-Path $Destination 'msodbcsql17.x64.msi'
    if (-not (Download-File -Url $redirectUrl -OutFile $outFile -VerifySignature)) {
        Write-Log "Failed to download ODBC Driver 17." "ERROR"
        return
    }
    if ($DryRun) { Write-Log "[DryRun] Would run: msiexec.exe /i `"$outFile`" /qb IACCEPTMSODBCSQLLICENSETERMS=YES ALLUSERS=1 /norestart" "INFO"; return }
    try {
        $installArgs = "/i `"$outFile`" /qb IACCEPTMSODBCSQLLICENSETERMS=YES ALLUSERS=1 /norestart"
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru
        if ($process.ExitCode -eq 0) { Write-Log "ODBC Driver 17 installed successfully." "SUCCESS" }
        elseif ($process.ExitCode -eq 3010) { Write-Log "ODBC Driver 17 installed; restart required." "WARN" }
        else { Write-Log "ODBC Driver 17 installer exit code $($process.ExitCode)" "WARN" }
    } catch {
        Write-Log "Failed to run msiexec for ODBC Driver 17: $_" "ERROR"
    }
    # NOTE: MSI is kept in $Destination for future use
}

function Install-OleDbDriver18 {
    Write-Log "Checking Microsoft OLE DB Driver 18..." "INFO"
    if (Test-OleDbDriver18Installed) {
        Write-Log "OLE DB Driver 18.6.5+ is already installed." "SUCCESS"
        return
    }
    Write-Log "OLE DB Driver 18.6.5+ not found. Preparing to download and install..." "WARN"
    $oleDbMsi = Join-Path $Destination 'msoledbsql.msi'
    if (-not (Download-File -Url $oleDbUrl -OutFile $oleDbMsi -VerifySignature)) {
        Write-Log "Failed to download OLE DB Driver installer." "ERROR"
        return
    }
    if ($DryRun) { Write-Log "[DryRun] Would run: msiexec.exe /i `"$oleDbMsi`" /quiet /norestart IACCEPTMSOLEDBSQLLICENSETERMS=YES" "INFO"; return }
    try {
        $installArgs = "/i `"$oleDbMsi`" /quiet /norestart IACCEPTMSOLEDBSQLLICENSETERMS=YES"
        $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $installArgs -Wait -PassThru
        if ($proc.ExitCode -eq 0) { Write-Log "OLE DB Driver 18 installed successfully." "SUCCESS" }
        elseif ($proc.ExitCode -eq 3010) { Write-Log "OLE DB Driver 18 installed; restart may be required." "WARN" }
        else { Write-Log "OLE DB installer exit code $($proc.ExitCode)" "WARN" }
    } catch {
        Write-Log "Failed to run OLE DB installer: $_" "ERROR"
    }
    # NOTE: MSI is intentionally kept in $Destination
}

# Region language configuration section.
Write-Log "Starting region language configuration..." "INFO"

if (-not $ConfirmLocaleChange) {
    Write-Log "Locale/system language change is disabled by default. Use -ConfirmLocaleChange to allow changes." "WARN"
} else {
    # Only proceed if user specifically confirmed
    try {
        if ($culture.Name -ne $regionLanguage) {
            Write-Log "User culture ($($culture.Name)) does not match target ($regionLanguage). Setting culture." "WARN"
            if (-not $DryRun) { Set-Culture $regionLanguage }
            Write-Log "User culture set to $regionLanguage." "SUCCESS"
        } else { Write-Log "User culture already $regionLanguage." "DEBUG" }

        if ($WinSystemLocale.Name -ne $regionLanguage) {
            Write-Log "System locale ($($WinSystemLocale.Name)) does not match target ($regionLanguage). Setting system locale." "WARN"
            if (-not $DryRun) { Set-WinSystemLocale $regionLanguage }
            Write-Log "System locale set to $regionLanguage." "SUCCESS"
        } else { Write-Log "System locale already $regionLanguage." "DEBUG" }

        if (-not ($Winuserlanguagelist.LanguageTag -contains $regionLanguage)) {
            Write-Log "User language list does not contain $regionLanguage. Adding..." "WARN"
            if (-not $DryRun) {
                $newLang = New-WinUserLanguageList $regionLanguage
                Set-WinUserLanguageList -LanguageList $newLang -Force
            }
            Write-Log "User language list updated to include $regionLanguage." "SUCCESS"
        } else { Write-Log "User language list already contains $regionLanguage." "DEBUG" }

        if ($Winhomelocation.GeoId -ne $Winhomelocationdefault) {
            Write-Log "Home location geoid ($($Winhomelocation.GeoId)) does not match target ($Winhomelocationdefault). Setting home location." "WARN"
            if (-not $DryRun) { Set-WinHomeLocation -GeoId $Winhomelocationdefault }
            Write-Log "Home location set to $Winhomelocationdefault." "SUCCESS"
        } else { Write-Log "Home location geoid already $Winhomelocationdefault." "DEBUG" }

        if (-not $DryRun) {
            Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true
            Write-Log "Copied user international settings to system and new user profiles." "SUCCESS"
        } else {
            Write-Log "[DryRun] Would copy user international settings to system and new user profiles." "INFO"
        }
    } catch {
        Write-Log "Locale configuration error: $_" "ERROR"
    }
}

# Download a backup script if missing
$cygateBackup = Join-Path $BackupFolder 'CygateScript.ps1'
if (Test-Path $cygateBackup) {
    Write-Log "CygateScript.ps1 already exists in Backup folder, skipping download." "INFO"
} else {
    Write-Log "CygateScript.ps1 missing in Backup folder; downloading..." "INFO"
    $cygateUrl = 'https://github.com/Dambergc/Vismascript/releases/latest/download/CygateScript.ps1'
    if (-not (Download-File -Url $cygateUrl -OutFile $cygateBackup -VerifySignature)) {
        Write-Log "Failed to download CygateScript.ps1" "WARN"
    }
}

# Run installs according to selected modes
if ($RunVIW) {
    Install-NetFramework48
}
if ($RunPUF -or $Runpuf) {  # keep case-insensitive compatibility
    Install-NetFramework48
    #Install-AspNetCore8
    Install-OleDbDriver18
    Install-VisualCRedistributable
    Install-OdbcDriver17
}
if ($RunBatch) {
    Install-NetFramework48
    #Install-AspNetCore8
    Install-OleDbDriver18
    Install-VisualCRedistributable
    Install-OdbcDriver17
}


Write-Log "Installation script completed. Check log file at $LogFile for details." "INFO"
Write-Log "If installations ran, please restart the computer for all changes to take effect (if required)." "WARN"
