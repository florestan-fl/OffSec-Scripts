# Create an output folder on Desktop or TEMP
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$baseDir = [Environment]::GetFolderPath('Desktop')
if (-not (Test-Path $baseDir)) {
    $baseDir = $env:TEMP
}

$OutDir = Join-Path $baseDir "SWIFT_TestHost_Inventory_$timestamp"
New-Item -ItemType Directory -Path $OutDir -ErrorAction SilentlyContinue | Out-Null
"Output directory: $OutDir"

 

# OS / hardware / environment
Get-ComputerInfo | Out-File -FilePath (Join-Path $OutDir "01_ComputerInfo.txt") -Width 500
 
systeminfo      | Out-File -FilePath (Join-Path $OutDir "01_SystemInfo.txt") -Width 500
hostname        | Out-File -FilePath (Join-Path $OutDir "01_Hostname.txt") -Width 200
whoami /all     | Out-File -FilePath (Join-Path $OutDir "01_Whoami_All.txt") -Width 500

 

# Installed software from registry (user-level view)
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"  -ErrorAction SilentlyContinue |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName |
    Out-File -FilePath (Join-Path $OutDir "02_InstalledSoftware_HKLM.txt") -Width 300
 
Get-ItemProperty "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName |
    Out-File -FilePath (Join-Path $OutDir "02_InstalledSoftware_HKLM_WOW6432.txt") -Width 300
 
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName |
    Out-File -FilePath (Join-Path $OutDir "02_InstalledSoftware_HKCU.txt") -Width 300

 

# Windows Defender and registered security products
Get-MpComputerStatus -ErrorAction SilentlyContinue |
    Out-File -FilePath (Join-Path $OutDir "03_WindowsDefenderStatus.txt") -Width 500
 
Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntivirusProduct" -ErrorAction SilentlyContinue |
    Out-File -FilePath (Join-Path $OutDir "03_SecurityCenter_Antivirus.txt") -Width 500
 
Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "FirewallProduct" -ErrorAction SilentlyContinue |
    Out-File -FilePath (Join-Path $OutDir "03_SecurityCenter_Firewall.txt") -Width 500

 

# Firewall profile state
netsh advfirewall show allprofiles |
    Out-File -FilePath (Join-Path $OutDir "04_Firewall_Profiles.txt") -Width 500
 
# Firewall rules (may be large)
netsh advfirewall firewall show rule name=all |
    Out-File -FilePath (Join-Path $OutDir "04_Firewall_Rules.txt") -Width 500

 

# AppLocker policies (if accessible as user)
Try {
    Get-AppLockerPolicy -Effective -ErrorAction Stop |
        Out-File -FilePath (Join-Path $OutDir "05_AppLocker_Effective.xml") -Width 500
} Catch {
    "Could not read AppLocker policy: $($_.Exception.Message)" |
        Out-File -FilePath (Join-Path $OutDir "05_AppLocker_Effective.txt")
}
 
# WDAC (Device Guard / Config Code Integrity) status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue |
    Out-File -FilePath (Join-Path $OutDir "05_DeviceGuard_Status.txt") -Width 500

 

# Running services
Get-Service | Sort-Object Status, DisplayName |
    Out-File -FilePath (Join-Path $OutDir "06_Services.txt") -Width 300
 
# Processes with company/security keywords highlighted
Get-Process | Sort-Object ProcessName |
    Out-File -FilePath (Join-Path $OutDir "06_Processes.txt") -Width 300

 

# IP config and interfaces
ipconfig /all |
    Out-File -FilePath (Join-Path $OutDir "07_IPConfig_All.txt") -Width 300
 
Get-NetIPAddress -ErrorAction SilentlyContinue |
    Out-File -FilePath (Join-Path $OutDir "07_NetIPAddress.txt") -Width 300
 
Get-NetRoute -ErrorAction SilentlyContinue |
    Out-File -FilePath (Join-Path $OutDir "07_NetRoutes.txt") -Width 300
 
# DNS settings
Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
    Out-File -FilePath (Join-Path $OutDir "07_DNSClientServerAddress.txt") -Width 300
 
# Proxy configuration (WinHTTP and IE/WinINET)
netsh winhttp show proxy |
    Out-File -FilePath (Join-Path $OutDir "07_WinHTTP_Proxy.txt") -Width 300
 
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" |
    Out-File -FilePath (Join-Path $OutDir "07_InternetSettings_Proxy.txt") -Width 300

 

# Active TCP connections (& listening ports)
netstat -ano |
    Out-File -FilePath (Join-Path $OutDir "08_Netstat_ano.txt") -Width 300
 
Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Out-File -FilePath (Join-Path $OutDir "08_GetNetTCPConnection.txt") -Width 300

 

# Who am I, groups, and domain info
whoami /all |
    Out-File -FilePath (Join-Path $OutDir "09_Whoami_All.txt") -Width 500
 
Try {
    Get-ADDomain -ErrorAction Stop |
        Out-File -FilePath (Join-Path $OutDir "09_AD_Domain.txt") -Width 500
} Catch {
    "Get-ADDomain failed (module not present or permissions). Message: $($_.Exception.Message)" |
        Out-File -FilePath (Join-Path $OutDir "09_AD_Domain.txt")
}

 

gpresult /R /Z |
    Out-File -FilePath (Join-Path $OutDir "10_GPResult.txt") -Width 500

 

# Check some standard paths for current user's access
$paths = @(
    "$env:ProgramFiles",
    "$env:ProgramFiles (x86)",
    "$env:ProgramData",
    "$env:SystemRoot",
    "$env:USERPROFILE",
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:TEMP"
)
 
$results = foreach ($p in $paths) {
    if (Test-Path $p) {
        try {
            $acl = Get-Acl -Path $p
            [PSCustomObject]@{
                Path             = $p
                AccessSummary    = ($acl.Access | Select-Object -First 5 |
                    ForEach-Object { "$($_.IdentityReference): $($_.FileSystemRights) ($($_.AccessControlType))" }) -join '; '
            }
        } catch {
            [PSCustomObject]@{
                Path          = $p
                AccessSummary = "Error: $($_.Exception.Message)"
            }
        }
    }
}
 
$results | Out-File -FilePath (Join-Path $OutDir "11_ACL_Summary_CommonPaths.txt") -Width 300

 

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Inventory.ps1

