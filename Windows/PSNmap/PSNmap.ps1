<#
.SYNOPSIS
    PSNmap - A comprehensive network scanner built entirely in PowerShell
    
.DESCRIPTION
    A feature-rich nmap-like tool for network discovery, port scanning, and service detection
    Built using only native PowerShell capabilities for maximum portability
    
.PARAMETER Target
    Single target host (IP or hostname) for port scanning
    
.PARAMETER Targets
    File containing list of targets (one per line)
    
.PARAMETER Range
    IP range for host discovery (format: 192.168.1.1-254)
    
.PARAMETER Ports
    Comma-separated port list or range (e.g., "80,443" or "1-1000")
    Default: Common ports if ServiceDB not available
    
.PARAMETER TopPorts
    Scan top N most common ports (requires ServiceDB)
    
.PARAMETER AllPorts
    Scan all 65535 ports (use with caution)
    
.PARAMETER ServiceDB
    Path to service-names-port-numbers.csv (IANA database)
    Download from: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
    
.PARAMETER ScanType
    Type of port scan to perform:
    - Connect: Full TCP connect (default, most compatible)
    
.PARAMETER ServiceDetection
    Enable service/version detection on open ports
    
.PARAMETER SSLCheck
    Perform SSL/TLS analysis on HTTPS ports
    
.PARAMETER Timeout
    Connection timeout in milliseconds (default: 1000)
    
.PARAMETER Threads
    Number of concurrent scanning threads (default: 50)
    
.PARAMETER OutputFormat
    Output format: Text (default), JSON, CSV, XML
    
.PARAMETER OutputFile
    Save results to file
    
.PARAMETER Verbose
    Enable verbose output
    
.EXAMPLE
    .\PSNmap.ps1 -Range 192.168.1.1-254
    Perform host discovery scan
    
.EXAMPLE
    .\PSNmap.ps1 -Target 192.168.1.1 -TopPorts 100 -ServiceDB .\service-names-port-numbers.csv
    Scan top 100 ports using IANA database
    
.EXAMPLE
    .\PSNmap.ps1 -Target example.com -Ports "80,443" -ServiceDetection -SSLCheck
    Scan specific ports with service detection and SSL analysis
    
.EXAMPLE
    .\PSNmap.ps1 -Target 192.168.1.1 -AllPorts -ServiceDB .\services.csv -Threads 200
    Full port scan with service names from database
#>

[CmdletBinding()]
param (
    [Parameter(ParameterSetName='Single')]
    [string]$Target,
    
    [Parameter(ParameterSetName='Multiple')]
    [string]$Targets,
    
    [Parameter(ParameterSetName='Discovery')]
    [string]$Range,
    
    [string]$Ports,
    
    [int]$TopPorts,
    
    [switch]$AllPorts,
    
    [string]$ServiceDB,
    
    [ValidateSet('Connect')]
    [string]$ScanType = 'Connect',
    
    [switch]$ServiceDetection,
    
    [switch]$SSLCheck,
    
    [int]$Timeout = 1000,
    
    [int]$Threads = 50,
    
    [ValidateSet('Text', 'JSON', 'CSV', 'XML')]
    [string]$OutputFormat = 'Text',
    
    [string]$OutputFile,
    
    [switch]$VerboseOutput
)

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================

$Script:Config = @{
    Version = "1.0.0"
    Banner = @"
  ____  ____  _   _                       
 |  _ \/ ___|| \ | |_ __ ___   __ _ _ __  
 | |_) \___ \|  \| | '_ `` _ \ / _`` | '_ \ 
 |  __/ ___) | |\  | | | | | | (_| | |_) |
 |_|   |____/|_| \_|_| |_| |_|\__,_| .__/ 
                                    |_|    
PSNmap $($Script:Config.Version) - PowerShell Network Scanner
"@
    Timeout = $Timeout
    Threads = $Threads
    ServiceDatabase = $null
}

# Fallback hardcoded common ports (used when no ServiceDB provided)
$Script:FallbackPorts = @{
    Top10 = @(80, 23, 443, 21, 22, 25, 3389, 110, 445, 139)
    Top20 = @(80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900)
    Top100 = @(
        7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,
        465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,
        1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,
        5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,
        49153,49154,49155,49156,49157
    )
}

# Service fingerprints for active probing
$Script:ServiceSignatures = @{
    SSH = @{
        Pattern = '^SSH-\d\.\d'
        Ports = @(22)
    }
    FTP = @{
        Pattern = '^220.*FTP|^220-|^220 .*FTP'
        Ports = @(21)
    }
    SMTP = @{
        Pattern = '^220.*SMTP|^220.*mail|^220-'
        Ports = @(25, 587)
    }
    HTTP = @{
        Pattern = '^HTTP/|^Server:|^<!DOCTYPE|^<html'
        Ports = @(80, 8080, 8000, 8008, 8081)
    }
    POP3 = @{
        Pattern = '^\+OK'
        Ports = @(110, 995)
    }
    IMAP = @{
        Pattern = '^\* OK'
        Ports = @(143, 993)
    }
}

# ============================================================================
# SERVICE DATABASE FUNCTIONS
# ============================================================================

function Import-ServiceDatabase {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        Write-Log "Service database not found: $Path" -Level Warning
        Write-Log "Download from: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv" -Level Info
        return $null
    }
    
    Write-Log "Loading service database from $Path..." -Level Verbose
    
    try {
        $csv = Import-Csv -Path $Path -ErrorAction Stop
        
        # Build hashtable for fast lookup: port/protocol -> service info
        $db = @{}
        
        foreach ($entry in $csv) {
            $portNum = $entry.'Port Number'
            $protocol = $entry.'Transport Protocol'
            $serviceName = $entry.'Service Name'
            $description = $entry.'Description'
            
            # Skip empty or invalid entries
            if (-not $portNum -or $portNum -notmatch '^\d+$') { continue }
            if (-not $protocol) { continue }
            
            $port = [int]$portNum
            $key = "$port/$protocol"
            
            # Only store TCP entries for now
            if ($protocol -eq 'tcp') {
                if (-not $db.ContainsKey($key)) {
                    $db[$key] = @{
                        Port = $port
                        Service = if ($serviceName) { $serviceName } else { "unknown" }
                        Description = $description
                        Protocol = $protocol
                    }
                }
            }
        }
        
        Write-Log "Loaded $($db.Count) TCP service definitions" -Level Success
        return $db
        
    } catch {
        Write-Log "Error loading service database: $_" -Level Error
        return $null
    }
}

function Get-TopPortsFromDB {
    param(
        [hashtable]$Database,
        [int]$Count = 100
    )
    
    # Well-known ports (0-1023) are generally more important
    # Then registered ports (1024-49151)
    # Then dynamic ports (49152-65535)
    
    $wellKnown = @()
    $registered = @()
    $dynamic = @()
    
    foreach ($key in $Database.Keys) {
        $port = $Database[$key].Port
        
        if ($port -le 1023) {
            $wellKnown += $port
        } elseif ($port -le 49151) {
            $registered += $port
        } else {
            $dynamic += $port
        }
    }
    
    # Return top ports prioritizing well-known, then registered
    $result = @()
    $result += $wellKnown | Sort-Object
    $result += $registered | Sort-Object
    $result += $dynamic | Sort-Object
    
    return ($result | Select-Object -First $Count)
}

function Get-ServiceNameFromDB {
    param(
        [hashtable]$Database,
        [int]$Port
    )
    
    $key = "$Port/tcp"
    
    if ($Database -and $Database.ContainsKey($key)) {
        $svc = $Database[$key]
        return @{
            Name = $svc.Service
            Description = $svc.Description
        }
    }
    
    # Fallback to basic mapping
    $basicServices = @{
        21 = "ftp"; 22 = "ssh"; 23 = "telnet"; 25 = "smtp"; 53 = "domain"
        80 = "http"; 110 = "pop3"; 111 = "rpcbind"; 135 = "msrpc"
        139 = "netbios-ssn"; 143 = "imap"; 443 = "https"; 445 = "microsoft-ds"
        587 = "submission"; 993 = "imaps"; 995 = "pop3s"; 1433 = "ms-sql-s"
        3306 = "mysql"; 3389 = "ms-wbt-server"; 5432 = "postgresql"
        5900 = "vnc"; 8080 = "http-proxy"; 8443 = "https-alt"
    }
    
    $name = if ($basicServices.ContainsKey($Port)) { $basicServices[$Port] } else { "unknown" }
    
    return @{
        Name = $name
        Description = ""
    }
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

function Write-Banner {
    Write-Host $Script:Config.Banner -ForegroundColor Cyan
    Write-Host ""
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Verbose')]
        [string]$Level = 'Info'
    )
    
    if ($Level -eq 'Verbose' -and -not $VerboseOutput) { return }
    
    $color = switch ($Level) {
        'Success' { 'Green' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Verbose' { 'Gray' }
        default { 'White' }
    }
    
    $prefix = switch ($Level) {
        'Success' { '[+]' }
        'Warning' { '[!]' }
        'Error' { '[-]' }
        'Verbose' { '[*]' }
        default { '' }
    }
    
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Parse-PortList {
    param([string]$PortString)
    
    $ports = @()
    
    foreach ($part in $PortString -split ',') {
        $part = $part.Trim()
        
        if ($part -match '^(\d+)-(\d+)$') {
            $start = [int]$Matches[1]
            $end = [int]$Matches[2]
            $ports += $start..$end
        }
        elseif ($part -match '^\d+$') {
            $ports += [int]$part
        }
    }
    
    return ($ports | Select-Object -Unique | Where-Object { $_ -ge 1 -and $_ -le 65535 })
}

function Get-PortList {
    if ($AllPorts) {
        Write-Log "Scanning all 65535 ports (this will take a while)..." -Level Warning
        return 1..65535
    }
    elseif ($TopPorts) {
        if ($Script:Config.ServiceDatabase) {
            $ports = Get-TopPortsFromDB -Database $Script:Config.ServiceDatabase -Count $TopPorts
            Write-Log "Using top $TopPorts ports from service database" -Level Verbose
            return $ports
        } else {
            Write-Log "No service database provided, using fallback port list" -Level Warning
            if ($TopPorts -le 10) { return $Script:FallbackPorts.Top10 }
            elseif ($TopPorts -le 20) { return $Script:FallbackPorts.Top20 }
            else { return $Script:FallbackPorts.Top100 }
        }
    }
    elseif ($Ports) {
        return Parse-PortList -PortString $Ports
    }
    else {
        # Default to top 10 common ports
        return $Script:FallbackPorts.Top10
    }
}

# ============================================================================
# HOST DISCOVERY
# ============================================================================

function Invoke-HostDiscovery {
    param([string]$IPRange)
    
    if ($IPRange -notmatch '^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$') {
        Write-Log "Invalid range format. Example: 192.168.1.1-254" -Level Error
        return
    }
    
    $base = $Matches[1]
    $start = [int]$Matches[2]
    $end = [int]$Matches[3]
    
    Write-Log "Starting host discovery scan on $IPRange" -Level Info
    Write-Host ""
    
    $jobs = @()
    $results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    
    $start..$end | ForEach-Object {
        $ip = "$base.$_"
        
        while ((Get-Job -State Running).Count -ge $Script:Config.Threads) {
            Start-Sleep -Milliseconds 100
        }
        
        $jobs += Start-Job -ScriptBlock {
            param($target)
            
            try {
                if (Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                    return @{
                        IP = $target
                        Status = 'Up'
                    }
                }
            } catch {}
            
            return $null
        } -ArgumentList $ip
    }
    
    $jobs | Wait-Job | ForEach-Object {
        $result = Receive-Job $_
        if ($result) {
            $results.Add($result)
            Write-Log "Host $($result.IP) is up" -Level Success
        }
        Remove-Job $_
    }
    
    Write-Host ""
    Write-Log "Discovered $($results.Count) host(s)" -Level Info
    
    return $results.ToArray()
}

# ============================================================================
# PORT SCANNING
# ============================================================================

function Invoke-PortScan {
    param(
        [string]$Target,
        [array]$PortList
    )
    
    Write-Log "Scanning $Target" -Level Info
    Write-Host ""
    
    # Host check
    try {
        $hostUp = Test-Connection -ComputerName $Target -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($hostUp) {
            Write-Log "Host is up" -Level Success
        } else {
            Write-Log "Host seems down, scanning anyway..." -Level Warning
        }
    } catch {
        Write-Log "Host status unknown, continuing..." -Level Warning
    }
    
    Write-Host ""
    Write-Host "PORT       STATE      SERVICE                DESCRIPTION"
    Write-Host "------------------------------------------------------------------------"
    
    $jobs = @()
    $results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    
    foreach ($port in $PortList) {
        while ((Get-Job -State Running).Count -ge $Script:Config.Threads) {
            Start-Sleep -Milliseconds 50
        }
        
        $jobs += Start-Job -ScriptBlock {
            param($target, $port, $timeout)
            
            try {
                $client = New-Object System.Net.Sockets.TcpClient
                $async = $client.BeginConnect($target, $port, $null, $null)
                $wait = $async.AsyncWaitHandle.WaitOne($timeout, $false)
                
                if ($wait -and $client.Connected) {
                    $client.Close()
                    return @{
                        Port = $port
                        State = 'open'
                    }
                }
                
                $client.Close()
            } catch {}
            
            return @{
                Port = $port
                State = 'filtered'
            }
        } -ArgumentList $Target, $port, $Script:Config.Timeout
    }
    
    $completed = 0
    $total = $jobs.Count
    
    $jobs | Wait-Job | ForEach-Object {
        $result = Receive-Job $_
        $results.Add($result)
        Remove-Job $_
        
        $completed++
        if ($completed % 100 -eq 0) {
            Write-Log "Progress: $completed/$total ports scanned" -Level Verbose
        }
    }
    
    $sortedResults = @($results.ToArray() | Sort-Object Port)
    
    foreach ($result in $sortedResults) {
        $serviceInfo = Get-ServiceNameFromDB -Database $Script:Config.ServiceDatabase -Port $result.Port
        $color = if ($result.State -eq 'open') { 'Green' } else { 'Gray' }
        
        $descDisplay = if ($serviceInfo.Description -and $serviceInfo.Description.Length -gt 30) {
            $serviceInfo.Description.Substring(0, 30) + "..."
        } else {
            $serviceInfo.Description
        }
        
        $line = "{0,-10} {1,-10} {2,-22} {3}" -f "$($result.Port)/tcp", $result.State, $serviceInfo.Name, $descDisplay
        Write-Host "Line:" $line -ForegroundColor $color
    }
    
    Write-Host ""
    $openCount = @($sortedResults | Where-Object { $_.State -eq 'open' }).Count
    Write-Log "Found $openCount open port(s)" -Level Info
    
    return $sortedResults
}

# ============================================================================
# SERVICE DETECTION
# ============================================================================

function Get-ServiceBanner {
    param(
        [string]$Target,
        [int]$Port,
        [int]$Timeout = 3000
    )
    
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.ReceiveTimeout = $Timeout
        $client.SendTimeout = $Timeout
        $client.Connect($Target, $Port)
        $stream = $client.GetStream()
        
        # Try passive banner grab first
        $buffer = New-Object byte[] 4096
        Start-Sleep -Milliseconds 500
        
        if ($stream.DataAvailable) {
            $bytes = $stream.Read($buffer, 0, $buffer.Length)
            $banner = [Text.Encoding]::ASCII.GetString($buffer, 0, $bytes)
            $stream.Close()
            $client.Close()
            return $banner.Trim()
        }
        
        # Try active probes
        $probes = @(
            "GET / HTTP/1.0`r`n`r`n",
            "HELP`r`n",
            "`r`n"
        )
        
        foreach ($probe in $probes) {
            try {
                $bytes = [Text.Encoding]::ASCII.GetBytes($probe)
                $stream.Write($bytes, 0, $bytes.Length)
                Start-Sleep -Milliseconds 500
                
                if ($stream.DataAvailable) {
                    $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                    $banner = [Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                    $stream.Close()
                    $client.Close()
                    return $banner.Trim()
                }
            } catch {
                continue
            }
        }
        
        $stream.Close()
        $client.Close()
    } catch {}
    
    return $null
}

function Get-ServiceInfo {
    param(
        [string]$Target,
        [int]$Port
    )
    
    $banner = Get-ServiceBanner -Target $Target -Port $Port
    $baseInfo = Get-ServiceNameFromDB -Database $Script:Config.ServiceDatabase -Port $Port
    
    $info = @{
        Port = $Port
        Service = $baseInfo.Name
        Version = "unknown"
        Banner = $banner
        Description = $baseInfo.Description
    }
    
    if ($banner) {
        # Pattern matching for version detection
        foreach ($sig in $Script:ServiceSignatures.Keys) {
            $pattern = $Script:ServiceSignatures[$sig].Pattern
            if ($pattern -and $banner -match $pattern) {
                $info.Service = $sig.ToLower()
                
                # Extract version info
                if ($banner -match '[\d\.]+') {
                    $info.Version = $Matches[0]
                }
                break
            }
        }
    }
    
    return $info
}

function Invoke-ServiceDetection {
    param(
        [string]$Target,
        [array]$OpenPorts
    )
    
    Write-Host ""
    Write-Log "Running service detection..." -Level Info
    Write-Host ""
    
    foreach ($portResult in $OpenPorts) {
        if ($portResult.State -ne 'open') { continue }
        
        Write-Log "Probing $($portResult.Port)/tcp..." -Level Verbose
        
        $serviceInfo = Get-ServiceInfo -Target $Target -Port $portResult.Port
        
        Write-Host "  Port $($serviceInfo.Port)/tcp"
        Write-Host "    Service: $($serviceInfo.Service)"
        
        if ($serviceInfo.Version -ne "unknown") {
            Write-Host "    Version: $($serviceInfo.Version)"
        }
        
        if ($serviceInfo.Banner) {
            $bannerPreview = $serviceInfo.Banner.Substring(0, [Math]::Min(100, $serviceInfo.Banner.Length))
            Write-Host "    Banner: $bannerPreview..."
        }
        
        Write-Host ""
    }
}

# ============================================================================
# SSL/TLS ANALYSIS
# ============================================================================

function Invoke-SSLCheck {
    param(
        [string]$Target,
        [array]$OpenPorts
    )
    
    # Check for HTTPS ports or known SSL/TLS services
    $sslPorts = $OpenPorts | Where-Object { 
        if ($_.State -ne 'open') { return $false }
        
        $serviceInfo = Get-ServiceNameFromDB -Database $Script:Config.ServiceDatabase -Port $_.Port
        $serviceName = $serviceInfo.Name
        
        # Check for HTTPS, IMAPS, POP3S, SMTPS, etc.
        return ($_.Port -eq 443 -or $_.Port -eq 8443 -or 
                $serviceName -match 'https|ssl|tls|imaps|pop3s|smtps')
    }
    
    if ($sslPorts.Count -eq 0) { return }
    
    Write-Host ""
    Write-Log "Running SSL/TLS analysis..." -Level Info
    Write-Host ""
    
    foreach ($portResult in $sslPorts) {
        $port = $portResult.Port
        $serviceInfo = Get-ServiceNameFromDB -Database $Script:Config.ServiceDatabase -Port $port
        
        Write-Host "  Port $port/tcp - $($serviceInfo.Name)"
        Write-Host "  " + ("-" * 50)
        
        # TLS Protocol enumeration
        $protocols = @{
            "TLS 1.0" = [System.Security.Authentication.SslProtocols]::Tls
            "TLS 1.1" = [System.Security.Authentication.SslProtocols]::Tls11
            "TLS 1.2" = [System.Security.Authentication.SslProtocols]::Tls12
        }
        
        # Add TLS 1.3 if available
        try {
            $protocols["TLS 1.3"] = 12288
        } catch {}
        
        $supported = @()
        $cert = $null
        
        foreach ($protoName in $protocols.Keys) {
            try {
                $client = New-Object System.Net.Sockets.TcpClient($Target, $port)
                $stream = New-Object System.Net.Security.SslStream(
                    $client.GetStream(),
                    $false,
                    { $true }
                )
                
                $stream.AuthenticateAsClient($Target, $null, $protocols[$protoName], $false)
                
                if ($stream.IsAuthenticated) {
                    $supported += $protoName
                    
                    if (-not $cert) {
                        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($stream.RemoteCertificate)
                    }
                }
                
                $stream.Close()
                $client.Close()
            } catch {}
        }
        
        if ($supported.Count -gt 0) {
            Write-Host "    Supported protocols: $($supported -join ', ')" -ForegroundColor Green
        } else {
            Write-Host "    No SSL/TLS protocols detected" -ForegroundColor Yellow
        }
        
        # Certificate info
        if ($cert) {
            Write-Host ""
            Write-Host "    Certificate:"
            Write-Host "      Subject: $($cert.Subject)"
            Write-Host "      Issuer: $($cert.Issuer)"
            Write-Host "      Valid: $($cert.NotBefore) to $($cert.NotAfter)"
            
            $now = Get-Date
            if ($cert.NotAfter -lt $now) {
                Write-Host "      Status: EXPIRED" -ForegroundColor Red
            } elseif (($cert.NotAfter - $now).Days -lt 30) {
                Write-Host "      Status: Expires soon ($(($cert.NotAfter - $now).Days) days)" -ForegroundColor Yellow
            } else {
                Write-Host "      Status: Valid" -ForegroundColor Green
            }
            
            # SANs
            $san = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
            if ($san) {
                Write-Host "      SANs: $($san.Format($false))"
            }
        }
        
        Write-Host ""
    }
}

# ============================================================================
# OUTPUT FORMATTING
# ============================================================================

function Export-Results {
    param(
        [object]$Results,
        [string]$Format,
        [string]$FilePath
    )
    
    switch ($Format) {
        'JSON' {
            $Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath
        }
        'CSV' {
            $Results | Export-Csv -Path $FilePath -NoTypeInformation
        }
        'XML' {
            $Results | Export-Clixml -Path $FilePath
        }
        'Text' {
            $Results | Out-File -FilePath $FilePath
        }
    }
    
    Write-Log "Results saved to $FilePath" -Level Success
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    Write-Banner
    
    # Load service database if provided
    if ($ServiceDB) {
        $Script:Config.ServiceDatabase = Import-ServiceDatabase -Path $ServiceDB
    }
    
    $startTime = Get-Date
    
    # HOST DISCOVERY MODE
    if ($Range) {
        $discoveredHosts = Invoke-HostDiscovery -IPRange $Range
        
        if ($OutputFile) {
            Export-Results -Results $discoveredHosts -Format $OutputFormat -FilePath $OutputFile
        }
        
        return
    }
    
    # PORT SCANNING MODE
    $targetList = @()
    
    if ($Target) {
        $targetList = @($Target)
    }
    elseif ($Targets) {
        if (Test-Path $Targets) {
            $targetList = Get-Content $Targets | Where-Object { $_ -and $_.Trim() }
        } else {
            Write-Log "Target file not found: $Targets" -Level Error
            return
        }
    }
    else {
        Write-Log "No target specified. Use -Target, -Targets, or -Range" -Level Error
        return
    }
    
    $portList = Get-PortList
    Write-Log "Scanning $($portList.Count) port(s)" -Level Info
    
    $allResults = @()
    
    foreach ($target in $targetList) {
        $scanResults = Invoke-PortScan -Target $target -PortList $portList
        
        $openPorts = $scanResults | Where-Object { $_.State -eq 'open' }
        
        if ($ServiceDetection -and $openPorts.Count -gt 0) {
            Invoke-ServiceDetection -Target $target -OpenPorts $openPorts
        }
        
        if ($SSLCheck -and $openPorts.Count -gt 0) {
            Invoke-SSLCheck -Target $target -OpenPorts $openPorts
        }
        
        $allResults += @{
            Target = $target
            Ports = $scanResults
            ScanTime = Get-Date
        }
    }
    
    # Summary
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-Host ""
    Write-Log "Scan completed in $([Math]::Round($duration.TotalSeconds, 2)) seconds" -Level Success
    
    # Export results if requested
    if ($OutputFile) {
        Export-Results -Results $allResults -Format $OutputFormat -FilePath $OutputFile
    }
}

Main
