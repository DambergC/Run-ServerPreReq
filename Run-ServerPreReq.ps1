
Param(
    [switch]$viw,
    [switch]$batch,
    [switch]$puf,
    [switch]$AllInOne
)


# Define download links.
# Aka.ms redirect links from Microsoft for the Visual C++ redistributables (these redirect to the current/latest binaries)
$links = @{
    'x86' = 'https://aka.ms/vs/17/release/vc_redist.x86.exe'
    'x64' = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'
}

# Official short redirect maintained by Microsoft for ODBC Driver 17 (points to latest)
$redirectUrl = 'https://go.microsoft.com/fwlink/?linkid=2266337'

# Microsoft redirect for the .NET Framework 4.8 installer (offline/web redirect)
$dotNetUrl = 'https://go.microsoft.com/fwlink/?linkid=2085155'

# Download URL for OLE DB Driver 18.6.5 x64
$oleDbUrl = 'https://go.microsoft.com/fwlink/?linkid=2218891'  # OLE DB Driver 18 x64


# Microsoft ASP.NET Core Runtime 8.x x64 download URL
$aspNetCoreUrl = 'https://builds.dotnet.microsoft.com/dotnet/aspnetcore/Runtime/8.0.21/dotnet-hosting-8.0.21-win.exe'


# Normalize/validate selection
$ModesSelected = @()
if ($viw)   { $ModesSelected += 'viw' }
if ($batch) { $ModesSelected += 'batch' }
if ($puf)   { $ModesSelected += 'puf' }
if ($AllInOne) { $ModesSelected = @('viw','batch','puf') }

if (($AllInOne -and ($viw -or $batch -or $puf)) -or (($ModesSelected.Count -gt 1) -and -not $AllInOne)) {
    Write-Error "Specify exactly one of -viw, -batch, -puf, or use -AllInOne. Conflicting selections detected."
    exit 1
}

$RunVIW   = $ModesSelected -contains 'viw'
$RunBatch = $ModesSelected -contains 'batch'
$RunPUF   = $ModesSelected -contains 'puf'
$RunAll   = $AllInOne.IsPresent

# If no mode selected, script will run but skip mode-specific installs
if ($ModesSelected.Count -eq 0) {
    Write-Host "No mode selected. Use -viw, -batch, -puf or -AllInOne. Default behavior will run common tasks only." -ForegroundColor Yellow
} else {
    Write-Host "Selected mode(s): $($ModesSelected -join ', ')" -ForegroundColor Cyan
}


# get current culture, system locale, user language list, and home location
$culture = Get-Culture
$WinSystemLocale = Get-WinSystemLocale
$Winuserlanguagelist = Get-WinUserLanguageList
$Winhomelocation = Get-WinHomeLocation

# Define values for the script  
$regionLanguage = 'sv-SE'  # Swedish (Sweden)
$Winhomelocationdefault = '221'  # Sweden
$Destination = "d:\visma\Install\Serverdownloads"
$backupFolder = "d:\visma\Install\Backup"

# Ensure the 'Visma Services Trusted Users' local group exists and add the current user to it
if ( -not (Get-LocalGroup 'Visma Services Trusted Users' -ErrorAction SilentlyContinue ))
{
   write-host -ForegroundColor Green 'Does not exist, creating it...'
   New-LocalGroup -Name 'Visma Services Trusted Users' -verbose
}
else
{
    write-host -ForegroundColor Green 'Local group exist'
}

# Add current user to the group if not already a member
$groupName = "Visma Services Trusted Users"
$currentUser = "$($env:USERDNSDOMAIN)\$($env:USERNAME)"

try {
    # Check if user is already a member
    $groupMembers = Get-LocalGroupMember -Group $groupName -ErrorAction SilentlyContinue
    $isAlreadyMember = $groupMembers | Where-Object { 
        $_.Name -eq $currentUser -or 
        $_.Name -eq $env:USERNAME -or 
        $_.Name -like "*\$($env:USERNAME)"
    }
    
    if ($isAlreadyMember) {
        Write-Host "User '$currentUser' is already a member of '$groupName'" -ForegroundColor Green
    } else {
        Write-Host "Adding '$currentUser' to '$groupName'" -ForegroundColor Green
        try {
            Add-LocalGroupMember -Member $currentUser -Group $groupName -Verbose
            Write-Host "Successfully added user to the group" -ForegroundColor Green
        } catch {
            if ($_.Exception.Message -like "*already a member*") {
                Write-Host "User '$currentUser' is already a member of '$groupName'" -ForegroundColor Green
            } else {
                throw
            }
        }
    }
} catch {
    Write-Warning "Failed to manage group membership for '$currentUser': $($_.Exception.Message)"
}




# Create destination folder
try {
    $null = New-Item -ItemType Directory -Path $Destination -Force
} catch {
    Write-Error "Unable to create or access destination folder '$Destination': $_"
    exit 1
}

# Create backup folder
try {
    $null = New-Item -ItemType Directory -Path $backupFolder -Force
} catch {
    Write-Error "Unable to create or access destination folder '$backupFolder': $_"
    exit 1
}

if (Test-Path "$backupFolder\CygateScript.ps1") {
    
    write-host -ForegroundColor Green 'CygateScript.ps1 already exists in Backup folder, skipping download.'
}
else {
    write-host -ForegroundColor Yellow 'CygateScript.ps1 does not exist in Backup folder, downloading...'
    Invoke-WebRequest 'https://github.com/Dambergc/Vismascript/releases/latest/download/CygateScript.ps1' -OutFile D:\Visma\Install\Backup\CygateScript.ps1 -Verbose
}



function Get-NetFxRelease {
    <#
    .SYNOPSIS
      Read .NET Framework v4 Full Release registry value.

    .OUTPUTS
      Hashtable with Release (int) and FriendlyVersion (string)
    #>
    $regPath = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
    $props = Get-ItemProperty -Path $regPath -Name Release -ErrorAction SilentlyContinue

    if (-not $props -or -not $props.Release) {
        return @{ Release = $null; FriendlyVersion = 'Not installed or unknown' }
    }

    $release = [int]$props.Release

    # Map release to friendly version (minimal mapping; >=528040 = 4.8+)
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
    <#
    .SYNOPSIS
      Returns $true if .NET Framework 4.8 (or later) is installed.
    .EXAMPLE
      if (Test-NetFx48Installed) { Write-Host ".NET 4.8+ present" }
    #>
    $info = Get-NetFxRelease
    if ($null -eq $info.Release) { return $false }
    return ($info.Release -ge 528040)
}

function Test-AspNetCore8Installed {
    <#
    .SYNOPSIS
      Returns $true if ASP.NET Core Runtime 8.x is installed.
    .DESCRIPTION
      Checks for ASP.NET Core Runtime version 8.x installation by looking at dotnet --list-runtimes output.
    #>
    
    try {
        # Check if dotnet command is available
        $dotnetPath = Get-Command dotnet -ErrorAction SilentlyContinue
        if (-not $dotnetPath) {
            return $false
        }
        
        # Get list of installed runtimes
        $runtimes = & dotnet --list-runtimes 2>$null
        if ($LASTEXITCODE -ne 0) {
            return $false
        }
        
        # Look for ASP.NET Core runtime version 8.x
        $aspNetCore8 = $runtimes | Where-Object { 
            $_ -match 'Microsoft\.AspNetCore\.App\s+8\.' 
        }
        
        return ($aspNetCore8.Count -gt 0)
    } catch {
        return $false
    }
}

function Install-AspNetCore8 {
    <#
    .SYNOPSIS
      Downloads and installs the latest ASP.NET Core Runtime 8.x (x64).
    .DESCRIPTION
      Downloads the ASP.NET Core Runtime installer from Microsoft and runs it silently.
    #>
    
    Write-Host "Checking ASP.NET Core Runtime 8..." -ForegroundColor Cyan
    
    if (Test-AspNetCore8Installed) {
        Write-Host "ASP.NET Core Runtime 8.x is already installed." -ForegroundColor Green
        return
    }
    
    Write-Host "ASP.NET Core Runtime 8.x not found. Downloading and installing..." -ForegroundColor Yellow
    
    try {
        # Ensure destination directory exists
        if (-not (Test-Path $Destination)) {
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        }
        
        # Define the local path for the ASP.NET Core hosting bundle installer
        $aspNetCoreExe = Join-Path $Destination 'dotnet-hosting-8.0.21-win.exe'

        
        Write-Host "Downloading ASP.NET Core Runtime 8 from: $aspNetCoreUrl" -ForegroundColor Cyan
        Write-Host "Saving to: $aspNetCoreExe" -ForegroundColor Cyan
        
        # Try Invoke-WebRequest first
        try {
            Invoke-WebRequest -Uri $aspNetCoreUrl -OutFile $aspNetCoreExe -Headers @{ 'User-Agent' = 'PowerShell' } -TimeoutSec 300 -ErrorAction Stop
            Write-Host "Download complete (Invoke-WebRequest)." -ForegroundColor Green
        } catch {
            Write-Host "Invoke-WebRequest failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "Trying alternative download method (WebClient)..." -ForegroundColor Cyan
            
            # Fallback to WebClient with TLS settings
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $webClient = New-Object System.Net.WebClient
                $webClient.Headers.Add('User-Agent', 'PowerShell')
                $webClient.DownloadFile($aspNetCoreUrl, $aspNetCoreExe)
                Write-Host "Download complete (WebClient)." -ForegroundColor Green
            } catch {
                throw "Both download methods failed. Last error: $($_.Exception.Message)"
            }
        }
        
        # Verify download
        if ((Test-Path $aspNetCoreExe) -and ((Get-Item $aspNetCoreExe).Length -gt 0)) {
            Write-Host "Installing ASP.NET Core Runtime 8..." -ForegroundColor Cyan
            
            # Install silently
            $installArgs = "/install /quiet /norestart"
            $proc = Start-Process -FilePath $aspNetCoreExe -ArgumentList $installArgs -Wait -PassThru
            
            if ($proc.ExitCode -eq 0) {
                Write-Host "ASP.NET Core Runtime 8 installation completed successfully." -ForegroundColor Green
            } elseif ($proc.ExitCode -eq 3010) {
                Write-Host "ASP.NET Core Runtime 8 installed successfully. A restart may be required." -ForegroundColor Yellow
            } else {
                Write-Warning "ASP.NET Core Runtime 8 installer exited with code: $($proc.ExitCode)"
            }
            
            # Clean up installer
            try {
                Remove-Item $aspNetCoreExe -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "Could not remove installer file: $aspNetCoreExe"
            }
        } else {
            throw "Downloaded ASP.NET Core Runtime installer is missing or empty: $aspNetCoreExe"
        }
    } catch {
        Write-Error "Failed to download or install ASP.NET Core Runtime 8: $_"
        # Continue execution; change to 'exit 1' if you want to abort on failure
    }
}
function Install-NetFramework48 {
    <#
    .SYNOPSIS
      Downloads and installs .NET Framework 4.8 if not already installed.
    .DESCRIPTION
      Downloads the .NET Framework 4.8 installer from Microsoft and runs it silently.
    #>
    
    Write-Host "Checking .NET Framework 4.8..." -ForegroundColor Cyan
    
    if (Test-NetFx48Installed) {
        Write-Host ".NET Framework 4.8 or later already installed." -ForegroundColor Green
        return
    }
    
    Write-Host ".NET Framework 4.8 (or later) not detected. Downloading and installing..." -ForegroundColor Yellow
    
    try {
        # Ensure destination directory exists
        if (-not (Test-Path $Destination)) {
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        }
        
        # Define the local path for the .NET Framework installer
        $dotNetExe = Join-Path $Destination 'ndp48-installer.exe'
        
        Write-Host "Downloading .NET Framework 4.8 from: $dotNetUrl" -ForegroundColor Cyan
        Write-Host "Saving to: $dotNetExe" -ForegroundColor Cyan
        
        # Download (Invoke-WebRequest with BITS fallback)
        try {
            Invoke-WebRequest -Uri $dotNetUrl -OutFile $dotNetExe -Headers @{ 'User-Agent' = 'PowerShell' } -TimeoutSec 600 -ErrorAction Stop
            Write-Host "Downloaded .NET 4.8 to: $dotNetExe" -ForegroundColor Green
        } catch {
            Write-Warning "Invoke-WebRequest failed: $($_.Exception.Message). Attempting BITS..."
            Start-BitsTransfer -Source $dotNetUrl -Destination $dotNetExe -ErrorAction Stop
            Write-Host "Downloaded .NET 4.8 (BITS) to: $dotNetExe" -ForegroundColor Green
        }

        # Verify file and run installer quietly
        if ((Test-Path $dotNetExe) -and ((Get-Item $dotNetExe).Length -gt 0)) {
            Write-Host "Installing .NET Framework 4.8..." -ForegroundColor Cyan
            $installArgs = '/q /norestart'
            $proc = Start-Process -FilePath $dotNetExe -ArgumentList $installArgs -Wait -PassThru

            if ($proc.ExitCode -eq 0) {
                Write-Host ".NET Framework 4.8 installation completed successfully." -ForegroundColor Green
            } elseif ($proc.ExitCode -eq 3010) {
                Write-Host ".NET Framework 4.8 installed successfully. A restart is required." -ForegroundColor Yellow
            } else {
                Write-Warning ".NET Framework 4.8 installer exited with code: $($proc.ExitCode)"
            }
            
            # Clean up installer
            try {
                Remove-Item $dotNetExe -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "Could not remove installer file: $dotNetExe"
            }
        } else {
            throw "Downloaded .NET installer is missing or empty: $dotNetExe"
        }
    } catch {
        Write-Error "Failed to download or install .NET Framework 4.8: $_"
        # continue to next steps; remove or change to 'exit 1' if you want to abort on failure
    }
}

function Test-VisualCRedistributableInstalled {
    [CmdletBinding()]
    param(
        [string]$DisplayNamePattern = 'Visual C\+\+|vcredist|vc_redist|Redistributable|Visual C Runtime',
        [ValidateSet('any','x86','x64')] [string]$Architecture = 'any',
        [string[]]$DllNames = @('msvcp140.dll','vcruntime140.dll','msvcr120.dll','msvcp120.dll','msvcr110.dll','msvcp110.dll'),
        [switch]$CheckDlls
    )

    # Registry uninstall locations to scan
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    # Find registry entries that match the pattern
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

    # Optionally check for common runtime DLLs in System32 and SysWOW64
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

    # Consider installed if registry shows it or any expected runtime DLL exists
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

function Install-VisualCRedistributable {
    <#
    .SYNOPSIS
      Downloads and installs Visual C++ Redistributables if not already installed.
    .DESCRIPTION
      Downloads the Visual C++ Redistributables (x86 and x64) from Microsoft and installs them silently.
    #>
    
    Write-Host "Checking Visual C++ Redistributables..." -ForegroundColor Cyan
    
    $vcplusplusinstalled = Test-VisualCRedistributableInstalled
    
    if ($vcplusplusinstalled.IsInstalled) {
        Write-Host "Visual C++ Redistributable is installed." -ForegroundColor Green
        return
    }
    
    Write-Host "Visual C++ Redistributable is not installed. Downloading and installing..." -ForegroundColor Yellow
    
    try {
        # Ensure destination directory exists
        if (-not (Test-Path $Destination)) {
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        }
        
        Write-Host "Starting download of Visual C++ Redistributables..." -ForegroundColor Cyan
        
        # Download Visual C++ Redistributables
        foreach ($arch in $links.Keys) {
            $url = $links[$arch]
            $outfile = Join-Path $Destination "vc_redist.$arch.exe"

            Write-Host "Downloading $arch redistributable from: $url" -ForegroundColor Cyan
            Write-Host "Saving to: $outfile" -ForegroundColor Cyan
            
            try {
                # Use Invoke-WebRequest to download the file
                Invoke-WebRequest -Uri $url -OutFile $outfile -Headers @{ 'User-Agent' = 'PowerShell' } -UseBasicParsing -TimeoutSec 300
                Write-Host "Downloaded $arch redistributable successfully." -ForegroundColor Green
            } catch {
                Write-Warning "Failed to download $arch from $url : $_"
                continue
            }
        }
        
        Write-Host "Download complete. Installing Visual C++ Redistributables..." -ForegroundColor Cyan

        # Install Visual C++ Redistributables
        foreach ($arch in $links.Keys) {
            $outfile = Join-Path $Destination "vc_redist.$arch.exe"
            
            if (Test-Path $outfile) {
                Write-Host "Installing Visual C++ Redistributable ($arch)..." -ForegroundColor Cyan
                try {
                    # Install with quiet mode and no restart
                    $installArgs = "/install /quiet /norestart"
                    $process = Start-Process -FilePath $outfile -ArgumentList $installArgs -Wait -PassThru
                    
                    if ($process.ExitCode -eq 0) {
                        Write-Host "Visual C++ Redistributable ($arch) installation completed successfully." -ForegroundColor Green
                    } elseif ($process.ExitCode -eq 3010) {
                        Write-Host "Visual C++ Redistributable ($arch) installation completed successfully. A restart is required." -ForegroundColor Yellow
                    } elseif ($process.ExitCode -eq 1638) {
                        Write-Host "Visual C++ Redistributable ($arch) is already installed or a newer version exists." -ForegroundColor Yellow
                    } else {
                        Write-Warning "Visual C++ Redistributable ($arch) installation completed with exit code: $($process.ExitCode)"
                    }
                    
                    # Clean up installer
                    try {
                        Remove-Item $outfile -Force -ErrorAction SilentlyContinue
                    } catch {
                        Write-Warning "Could not remove installer file: $outfile"
                    }
                } catch {
                    Write-Error "Failed to install Visual C++ Redistributable ($arch): $_"
                }
            } else {
                Write-Warning "Visual C++ Redistributable ($arch) file not found: $outfile"
            }
        }

        Write-Host "Visual C++ Redistributables installation completed." -ForegroundColor Green
    } catch {
        Write-Error "Failed to download or install Visual C++ Redistributables: $_"
        # Continue execution; change to 'exit 1' if you want to abort on failure
    }
}

function Install-OdbcDriver17 {
    <#
    .SYNOPSIS
      Downloads and installs Microsoft ODBC Driver 17 for SQL Server (x64) if not already installed.
    .DESCRIPTION
      Downloads the ODBC Driver installer from Microsoft and runs it silently.
    #>
    
    Write-Host "Checking Microsoft ODBC Driver 17 for SQL Server..." -ForegroundColor Cyan
    
    if (Test-OdbcDriver17Installed) {
        Write-Host "Microsoft ODBC Driver 17 for SQL Server is already installed." -ForegroundColor Green
        return
    }
    
    Write-Host "Microsoft ODBC Driver 17 for SQL Server not found. Downloading and installing..." -ForegroundColor Yellow
    
    try {
        # Ensure destination directory exists
        if (-not (Test-Path $Destination)) {
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        }
        
        # Define the local path for the ODBC driver installer
        $outFile = Join-Path $Destination 'msodbcsql17.x64.msi'
        
        Write-Host "Downloading Microsoft ODBC Driver 17 from: $redirectUrl" -ForegroundColor Cyan
        Write-Host "Saving to: $outFile" -ForegroundColor Cyan

        # Try Invoke-WebRequest first
        try {
            Invoke-WebRequest -Uri $redirectUrl -OutFile $outFile -Headers @{ 'User-Agent' = 'PowerShell' } -TimeoutSec 300 -ErrorAction Stop
            Write-Host "Download complete (Invoke-WebRequest)." -ForegroundColor Green
        } catch {
            Write-Warning "Invoke-WebRequest failed: $($_.Exception.Message). Attempting BITS (Start-BitsTransfer) as a fallback..."
            try {
                Start-BitsTransfer -Source $redirectUrl -Destination $outFile -Priority High -ErrorAction Stop
                Write-Host "Download complete (BITS)." -ForegroundColor Green
            } catch {
                throw "Both Invoke-WebRequest and Start-BitsTransfer failed: $($_.Exception.Message)"
            }
        }

        # Verify download and install
        if ((Test-Path $outFile) -and ((Get-Item $outFile).Length -gt 0)) {
            Write-Host "Installing Microsoft ODBC Driver 17 (x64)..." -ForegroundColor Cyan
            
            try {
                $installArgs = "/i `"$outFile`" /qb IACCEPTMSODBCSQLLICENSETERMS=YES ALLUSERS=1 /norestart"
                $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru
                
                if ($process.ExitCode -eq 0) {
                    Write-Host "Microsoft ODBC Driver 17 (x64) installation completed successfully." -ForegroundColor Green
                } elseif ($process.ExitCode -eq 3010) {
                    Write-Host "Microsoft ODBC Driver 17 (x64) installation completed successfully. A restart is required." -ForegroundColor Yellow
                } else {
                    Write-Warning "Installation completed with exit code: $($process.ExitCode). Please check if installation was successful."
                }
                
                # Clean up installer
                try {
                    Remove-Item $outFile -Force -ErrorAction SilentlyContinue
                } catch {
                    Write-Warning "Could not remove installer file: $outFile"
                }
            } catch {
                Write-Error "Failed to run the installer: $_"
            }
        } else {
            throw "Download completed but file is missing or empty: $outFile"
        }

    } catch {
        Write-Error "Failed to download or install Microsoft ODBC Driver 17: $_"
        # Continue execution; change to 'exit 1' if you want to abort on failure
    }
}

# Added: check for Microsoft ODBC Driver 17 for SQL Server
function Test-OdbcDriver17Installed {
    <#
    .SYNOPSIS
      Returns $true if "ODBC Driver 17 for SQL Server" is installed (checks 64- and 32-bit registry locations).
    #>
    $driverName = 'ODBC Driver 17 for SQL Server'

    # Check ODBC Drivers listing (both registry views)
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

    # Also check the specific driver key for Driver/Setup values
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
    .SYNOPSIS
      Returns $true if Microsoft OLE DB Driver 18 for SQL Server (version 18.6.5 or later) is installed.
    .DESCRIPTION
      Checks registry for OLE DB Provider installation and verifies version 18.6.5 or later.
      Also downloads and installs the driver if not found.
    #>
    
    # Check registry for OLE DB Provider
    $oleDbRegPaths = @(
        'HKLM:\SOFTWARE\Classes\CLSID\{0C7FF16C-38E3-11d0-97AB-00C04FC2AD98}\InprocServer32',
        'HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID\{0C7FF16C-38E3-11d0-97AB-00C04FC2AD98}\InprocServer32'
    )
    
    $providerFound = $false
    $correctVersion = $false
    
    foreach ($regPath in $oleDbRegPaths) {
        if (Test-Path $regPath) {
            try {
                $props = Get-ItemProperty -Path $regPath -ErrorAction Stop
                if ($props.'(default)' -and $props.'(default)' -match 'msoledbsql') {
                    $providerFound = $true
                    
                    # Check version from the DLL
                    $dllPath = $props.'(default)'
                    if (Test-Path $dllPath) {
                        $fileVersion = (Get-ItemProperty $dllPath).VersionInfo.FileVersion
                        if ($fileVersion) {
                            $version = [System.Version]$fileVersion
                            $targetVersion = [System.Version]"18.6.5"
                            if ($version -ge $targetVersion) {
                                $correctVersion = $true
                                break
                            }
                        }
                    }
                }
            } catch {
                continue
            }
        }
    }
    
    # Also check uninstall registry entries
    if (-not $providerFound) {
        $uninstallPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        
        foreach ($path in $uninstallPaths) {
            $entries = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -match 'Microsoft OLE DB Driver.*for SQL Server' }
            
            foreach ($entry in $entries) {
                if ($entry.DisplayVersion) {
                    try {
                        $version = [System.Version]$entry.DisplayVersion
                        $targetVersion = [System.Version]"18.6.5"
                        if ($version -ge $targetVersion) {
                            $providerFound = $true
                            $correctVersion = $true
                            break
                        }
                    } catch {
                        continue
                    }
                }
            }
            if ($correctVersion) { break }
        }
    }
    
    return ($providerFound -and $correctVersion)
}

function Install-OleDbDriver18 {
    <#
    .SYNOPSIS
      Downloads and installs Microsoft OLE DB Driver 18.6.5 for SQL Server (x64).
    .DESCRIPTION
      Downloads the OLE DB Driver installer from Microsoft and runs it silently.
    #>
    
    Write-Host "Checking Microsoft OLE DB Driver 18 for SQL Server..." -ForegroundColor Cyan
    
    if (Test-OleDbDriver18Installed) {
        Write-Host "Microsoft OLE DB Driver 18.6.5+ for SQL Server (x64) is already installed." -ForegroundColor Green
        return
    }
    
    Write-Host "Microsoft OLE DB Driver 18.6.5+ not found. Downloading and installing..." -ForegroundColor Yellow
    
    try {
        # Ensure destination directory exists
        if (-not (Test-Path $Destination)) {
            New-Item -ItemType Directory -Path $Destination -Force | Out-Null
        }
        
        # Define the local path for the OLE DB driver installer
        $oleDbExe = Join-Path $Destination 'msoledbsql.msi'

        
        Write-Host "Downloading OLE DB Driver from: $oleDbUrl" -ForegroundColor Cyan
        Write-Host "Saving to: $oleDbExe" -ForegroundColor Cyan
        
        # Try Invoke-WebRequest first
        try {
            Invoke-WebRequest -Uri $oleDbUrl -OutFile $oleDbExe -Headers @{ 'User-Agent' = 'PowerShell' } -TimeoutSec 300 -ErrorAction Stop
            Write-Host "Download complete (Invoke-WebRequest)." -ForegroundColor Green
        } catch {
            Write-Host "Invoke-WebRequest failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "Trying alternative download method (WebClient)..." -ForegroundColor Cyan
            
            # Fallback to WebClient with TLS settings
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $webClient = New-Object System.Net.WebClient
                $webClient.Headers.Add('User-Agent', 'PowerShell')
                $webClient.DownloadFile($oleDbUrl, $oleDbExe)
                Write-Host "Download complete (WebClient)." -ForegroundColor Green
            } catch {
                throw "Both download methods failed. Last error: $($_.Exception.Message)"
            }
        }
        
        # Verify download
        if ((Test-Path $oleDbExe) -and ((Get-Item $oleDbExe).Length -gt 0)) {
            Write-Host "Installing Microsoft OLE DB Driver 18..." -ForegroundColor Cyan
            
            # Install MSI silently
            $installArgs = "/i `"$oleDbExe`" /quiet /norestart IACCEPTMSOLEDBSQLLICENSETERMS=YES"
            $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $installArgs -Wait -PassThru
            
            if ($proc.ExitCode -eq 0) {
                Write-Host "Microsoft OLE DB Driver 18 installation completed successfully." -ForegroundColor Green
            } elseif ($proc.ExitCode -eq 3010) {
                Write-Host "Microsoft OLE DB Driver 18 installed successfully. A restart may be required." -ForegroundColor Yellow
            } else {
                Write-Warning "OLE DB Driver installer exited with code: $($proc.ExitCode)"
            }
            
            # Clean up installer
            try {
                Remove-Item $oleDbExe -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Warning "Could not remove installer file: $oleDbExe"
            }
        } else {
            throw "Downloaded OLE DB Driver installer is missing or empty: $oleDbExe"
        }
    } catch {
        Write-Error "Failed to download or install Microsoft OLE DB Driver 18: $_"
        # Continue execution; change to 'exit 1' if you want to abort on failure
    }
}


# Region language configuration section.
Write-Host "Starting region language configuration..." -ForegroundColor Cyan

# Check if the current culture matches the expected region language
if ($culture.Name -ne $regionLanguage) {
    Write-Host "Warning: The user culture ($($culture.Name)) does not match the expected region language ($regionLanguage)." -ForegroundColor Red
    Set-Culture $regionLanguage
    Write-Host "User culture has been set to: $regionLanguage" -ForegroundColor Green
}
    else {
        Write-Host "User culture matches the expected region language: $regionLanguage" -ForegroundColor Green
    }

# Check if the current system locale matches the expected region language
if ($WinSystemLocale.Name -ne $regionLanguage) {
        Write-Host "Warning: The system locale ($($WinSystemLocale.Name)) does not match the expected region language ($regionLanguage)." -ForegroundColor Red
        Set-WinSystemLocale $regionLanguage
        Write-Host "System locale has been set to: $regionLanguage" -ForegroundColor Green
     }
    else {
        Write-Host "System locale matches the expected region language: $regionLanguage" -ForegroundColor Green
    }

# Check if the user language list contains the expected region language
if (-not ($Winuserlanguagelist.LanguageTag -contains $regionLanguage)) {
        Write-Host "Warning: The user language list does not contain the expected region language ($regionLanguage)." -ForegroundColor Red
        $newLang = New-WinUserLanguageList $regionLanguage
        Set-WinUserLanguageList -LanguageList $newLang -Force
        Write-Host "User language list has been updated to include: $regionLanguage" -ForegroundColor Green
     }
    else {
        Write-Host "User language list contains the expected region language: $regionLanguage" -ForegroundColor Green
    }

# Check if the home location matches the expected geoid
if ($Winhomelocation.GeoId -ne $Winhomelocationdefault) {
        Write-Host "Warning: The home location geoid ($($Winhomelocation.GeoId)) does not match the expected geoid $Winhomelocationdefault." -ForegroundColor Red
        Set-WinHomeLocation -GeoId $Winhomelocationdefault
        Write-Host "Home location geoid has been set to: 221 (Sweden)" -ForegroundColor Green
     }
    else {
        Write-Host "Home location geoid matches the expected geoid: 221 (Sweden)" -ForegroundColor Green
    }

Write-Host "Region language configuration completed." -ForegroundColor Cyan

Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true

Write-Host "Copied user international settings to system and new user profiles." -ForegroundColor Cyan

if ($RunVIW) {
    Install-NetFramework48
}

if ($Runpuf) {
    Install-NetFramework48
    Install-AspNetCore8
    Install-OleDbDriver18
    Install-VisualCRedistributable
    Install-OdbcDriver17
}

if ($RunBatch) {
    Install-NetFramework48
    Install-OleDbDriver18
    Install-VisualCRedistributable
    Install-OdbcDriver17
}

if($RunAll) {
    Install-NetFramework48
    Install-AspNetCore8
    Install-OleDbDriver18
    Install-VisualCRedistributable
    Install-OdbcDriver17
}




Write-Host "Please restart the computer for all changes to take effect." -ForegroundColor Yellow