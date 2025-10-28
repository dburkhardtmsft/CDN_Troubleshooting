# CDN Network Diagnostics Tool
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Url,
    
    [Parameter(Mandatory=$false)]
    [string]$CdnType = "Unknown",  # Can be "Azure Front Door", "CloudFront", or "Unknown"
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("1.2", "1.3")]
    [string]$TlsVersion
)

function Show-IterationMenu {
    Clear-Host
    Write-Host "How many times do you want to run each test? (Ideally 100 times for best baseline)" -ForegroundColor Cyan
    Write-Host "A: 20 iterations"
    Write-Host "B: 50 iterations"
    Write-Host "C: 100 iterations"
    
    $choice = Read-Host "Enter your choice (A/B/C)"
    
    switch ($choice.ToUpper()) {
        "A" { return 20 }
        "B" { return 50 }
        "C" { return 100 }
        default {
            Write-Host "Invalid choice. Defaulting to 20 iterations." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            return 20
        }
    }
}

# Get number of iterations from user
$Iterations = Show-IterationMenu

# Import required utility functions
function Get-DnsInformation {
    param([string]$hostname)
    
    $dnsInfo = @{
        Domain = $hostname
        IPs = @()
        CNAMEs = @()
        SOA = $null
    }
    
    try {
        # Get IP addresses
        $ips = [System.Net.Dns]::GetHostAddresses($hostname)
        foreach($ip in $ips) {
            $ipInfo = @{
                Address = $ip.ToString()
                Owner = "Unknown"
                Location = "Unknown"
            }
            
            # Try to get IP information using nslookup
            try {
                $whois = nslookup $ip.ToString() 2>$null
                $whoResponse = $whois | Out-String
                
                # Try to get organization
                if ($whoResponse -match "(?i)organization:\s*(.+)") {
                    $ipInfo.Owner = $matches[1].Trim()
                }
                
                # Try to get location from Azure or Microsoft IP
                if ($whoResponse -match "(?i)location:\s*(.+)") {
                    $ipInfo.Location = $matches[1].Trim()
                } elseif ($whoResponse -match "(?i)city:\s*(.+)") {
                    $location = $matches[1].Trim()
                    if ($whoResponse -match "(?i)state:\s*(.+)") {
                        $location += ", " + $matches[1].Trim()
                    }
                    if ($whoResponse -match "(?i)country:\s*(.+)") {
                        $location += ", " + $matches[1].Trim()
                    }
                    $ipInfo.Location = $location
                }
            } catch { }
            
            $dnsInfo.IPs += $ipInfo
        }
        
        # Get CNAME chain
        $domain = $hostname
        $seen = @{}
        while ($true) {
            if ($seen.ContainsKey($domain)) { break }
            $seen[$domain] = $true
            
            $nslookup = nslookup -type=CNAME $domain 2>$null
            $cname = $null
            $ttl = 60  # Default TTL
            $nslookup | ForEach-Object {
                if ($_ -match 'ttl\s*=\s*(\d+)') {
                    $ttl = $matches[1]
                }
                if ($_ -match 'canonical name = (.+)') {
                    $cname = $matches[1].Trim('.')
                    $dnsInfo.CNAMEs += @{
                        From = $domain
                        To = $cname
                        TTL = $ttl
                    }
                    $domain = $cname
                }
            }
            if (-not $cname) { break }
        }
        
        # Get SOA record
        $soa = nslookup -type=SOA $hostname 2>$null
        $soaInfo = @{}
        if ($soa -match 'primary name server = (.+)') { $soaInfo.Name = $matches[1].Trim('.') }
        if ($soa -match 'responsible mail addr = (.+)') { $soaInfo.Admin = $matches[1].Trim('.') }
        if ($soa -match 'serial\s+=\s+(\d+)') { $soaInfo.Serial = $matches[1] }
        if ($soa -match 'refresh\s+=\s+(\d+)') { $soaInfo.Refresh = $matches[1] }
        if ($soa -match 'retry\s+=\s+(\d+)') { $soaInfo.Retry = $matches[1] }
        if ($soa -match 'expire\s+=\s+(\d+)') { $soaInfo.Expire = $matches[1] }
        if ($soa -match 'default TTL\s+=\s+(\d+)') { $soaInfo.DefaultTTL = $matches[1] }
        $dnsInfo.SOA = $soaInfo
    } catch {
        Write-Verbose "Error getting DNS information: $_"
    }
    
    return $dnsInfo
}

function Get-P95 {
    param([float[]]$values)
    $sorted = $values | Sort-Object
    $count = $sorted.Count
    if ($count -eq 0) { return $null }
    $index = [math]::Ceiling(0.95 * $count) - 1
    return $sorted[$index]
}

function Get-P98 {
    param([float[]]$values)
    $sorted = $values | Sort-Object
    $count = $sorted.Count
    if ($count -eq 0) { return $null }
    $index = [math]::Ceiling(0.98 * $count) - 1
    return $sorted[$index]
}

function Get-Statistics {
    param([float[]]$values)
    $stats = @{
        Average = ($values | Measure-Object -Average).Average
        Median = $values | Sort-Object | Select-Object -Index ([math]::Floor($values.Count / 2))
        StdDev = [math]::Sqrt(($values | ForEach-Object { [math]::Pow($_ - ($values | Measure-Object -Average).Average, 2) } | Measure-Object -Average).Average)
        P95 = Get-P95 -values $values
        P98 = Get-P98 -values $values
        Min = ($values | Measure-Object -Minimum).Minimum
        Max = ($values | Measure-Object -Maximum).Maximum
        Count = $values.Count
    }
    return $stats
}

# Configure TLS version if specified
$script:forcedTlsVersion = switch ($TlsVersion) {
    "1.2" {
        Write-Host "Enforcing TLS 1.2 for all requests..." -ForegroundColor Yellow
        [Net.SecurityProtocolType]::Tls12
    }
    "1.3" {
        Write-Host "Enforcing TLS 1.3 for all requests..." -ForegroundColor Yellow
        [Net.SecurityProtocolType]::Tls13
    }
    default {
        Write-Host "Using system default TLS version." -ForegroundColor Yellow
        $null
    }
}

if ($script:forcedTlsVersion) {
    [Net.ServicePointManager]::SecurityProtocol = $script:forcedTlsVersion
}

# Clean up existing connections and DNS cache
[System.Net.ServicePointManager]::DnsRefreshTimeout = 0

# Configure ServicePoint behavior
$servicePoint = [System.Net.ServicePointManager]::FindServicePoint([Uri]$Url)
$servicePoint.ConnectionLimit = 1  # Ensure sequential connections
$servicePoint.Expect100Continue = $false
$servicePoint.UseNagleAlgorithm = $false  # Disable Nagle's algorithm for more accurate timing
$servicePoint.MaxIdleTime = 0  # Don't keep connections alive between tests

# Initialize timing arrays
$latencies = @()
$ttfbs = @()
$hitMisses = @()
$sslLatencies = @()
$dnsTimings = @()
$tcpTimings = @()
$serverTimings = @()
$downloadTimings = @()

# Initialize tracking
$responseCodes = @{}
$azureRefStats = @{}

# Create a dedicated connection pool for our measurements
$servicePoint = [System.Net.ServicePointManager]::FindServicePoint([Uri]$Url)
$servicePoint.ConnectionLimit = 1  # Ensure sequential connections for accurate timing
$servicePoint.Expect100Continue = $false  # Reduce overhead

# Parse hostname from URL
$uri = [System.Uri]$Url
$hostname = $uri.Host

Write-Host "Starting diagnostics for URL: $Url" -ForegroundColor Cyan
Write-Host "Running $Iterations iterations..." -ForegroundColor Yellow

# Define measurement functions
function Get-SSLHandshakeLatency {
    param([string]$Hostname)
    
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        
        # Measure TCP connection time
        $client.Connect($Hostname, 443)
        $tcpTime = $sw.ElapsedMilliseconds
        
        # Measure SSL handshake time
        $sslStream = New-Object System.Net.Security.SslStream($client.GetStream(), $false)
        $sslStream.AuthenticateAsClient($Hostname)
        $sslTime = $sw.ElapsedMilliseconds - $tcpTime
        
        # Get certificate validation time
        $certTime = $sw.ElapsedMilliseconds - $sslTime - $tcpTime
        
        $client.Close()
        return @{
            TcpConnectionTime = $tcpTime
            SslHandshakeTime = $sslTime
            CertValidationTime = $certTime
        }
    }
    catch {
        Write-Verbose "SSL measurement failed: $_"
        return $null
    }
}

function Get-DetailedTimings {
    param([string]$Url)
    
    $result = @{
        DnsLookup = 0
        TcpConnect = 0
        ServerProcessing = 0
        ContentDownload = 0
    }
    
    try {
        $uri = [System.Uri]$Url
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        
        # Clear DNS cache and prepare for fresh connection
        [System.Net.ServicePointManager]::DnsRefreshTimeout = 0
        [void]$servicePoint.CloseConnectionGroup("")
        
        # Measure DNS lookup
        $addrs = [System.Net.Dns]::GetHostAddresses($uri.Host)
        $result.DnsLookup = $sw.ElapsedMilliseconds
        
        # Measure TCP connection
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect($uri.Host, $uri.Port)
        $result.TcpConnect = $sw.ElapsedMilliseconds - $result.DnsLookup
        $client.Close()
        
        # Measure server processing and download
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = "GET"
        $startProcess = $sw.ElapsedMilliseconds
        $resp = $req.GetResponse()
        $result.ServerProcessing = $sw.ElapsedMilliseconds - $startProcess
        
        # Measure content download
        $stream = $resp.GetResponseStream()
        $buffer = New-Object byte[] 8192
        while ($stream.Read($buffer, 0, $buffer.Length) -gt 0) {}
        $result.ContentDownload = $sw.ElapsedMilliseconds - $startProcess - $result.ServerProcessing
        
        $resp.Close()
    }
    catch {
        Write-Verbose "Detailed timing measurement failed: $_"
    }
    
    return $result
}

function Get-TrueCompressedSize {
    param([System.Net.HttpWebResponse]$Response)
    
    try {
        $encoding = $Response.Headers["Content-Encoding"]
        if (-not $encoding) { return $Response.ContentLength }
        
        $stream = $Response.GetResponseStream()
        switch -regex ($encoding.ToLower()) {
            "gzip" { $stream = New-Object System.IO.Compression.GZipStream($stream, [IO.Compression.CompressionMode]::Decompress) }
            "deflate" { $stream = New-Object System.IO.Compression.DeflateStream($stream, [IO.Compression.CompressionMode]::Decompress) }
        }
        
        $ms = New-Object System.IO.MemoryStream
        $buffer = New-Object byte[] 8192
        $total = 0
        $count = 0
        
        while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $ms.Write($buffer, 0, $count)
            $total += $count
        }
        
        return $total
    }
    catch {
        Write-Verbose "Compressed size measurement failed: $_"
        return $null
    }
}

# Perform warmup request to ensure DNS cache and connections are initialized
try {
    $warmupRequest = [System.Net.WebRequest]::Create($Url)
    $warmupRequest.Method = "HEAD"
    $warmupResponse = $warmupRequest.GetResponse()
    $warmupResponse.Close()
    Start-Sleep -Seconds 1  # Allow connections to settle
}
catch {
    Write-Verbose "Warmup request failed: $_"
}

# Main diagnostic loop
for ($i = 1; $i -le $Iterations; $i++) {
    Write-Progress -Activity "Running Network Diagnostics" -Status "Test $i of $Iterations" -PercentComplete (($i / $Iterations) * 100)
    
    # Force cleanup of existing connections
    [void]$servicePoint.CloseConnectionGroup("")
    [System.Net.ServicePointManager]::DnsRefreshTimeout = 0
    [System.GC]::Collect()  # Help clean up network resources
    Start-Sleep -Milliseconds 100  # Allow connections to fully close
    
    # Get detailed timings
    $detailedTimings = Get-DetailedTimings -Url $Url
    $dnsTimings += $detailedTimings.DnsLookup
    $tcpTimings += $detailedTimings.TcpConnect
    $serverTimings += $detailedTimings.ServerProcessing
    $downloadTimings += $detailedTimings.ContentDownload
    
    # Measure SSL handshake latency
    $sslLatency = Get-SSLHandshakeLatency -Hostname $hostname
    if ($sslLatency) {
        $sslLatencies += $sslLatency
    }

    # Measure pure HTTP response time (using established connection)
    Start-Sleep -Milliseconds 200  # Ensure previous connection is fully established
    
    # First make a warmup request to ensure connection is ready
    try {
        $warmupReq = [System.Net.WebRequest]::Create($Url)
        $warmupReq.Method = "HEAD"
        $warmupReq.GetResponse().Close()
    } catch { }
    
    # Now measure the actual HTTP request/response cycle
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $resp = $null
    try {
        # Create a custom WebRequest for just HTTP layer timing
        $req = [System.Net.WebRequest]::Create($Url)
        $req.Method = "GET"
        $req.AllowAutoRedirect = $false
        $req.KeepAlive = $true
        $req.Headers.Add("Accept-Encoding", "gzip, deflate")
        $req.Headers.Add("Accept", "text/html")
        $req.ServicePoint.ConnectionLimit = 1
        $req.ServicePoint.UseNagleAlgorithm = $false
        $resp = $req.GetResponse()
        # Track successful response code
        $code = [int]$resp.StatusCode
        $responseCodes[$code] = ($responseCodes[$code] + 1) ?? 1

        # Check for CDN-specific headers if we got a response
        $headers = $resp.Headers
        if ($headers) {
            # Azure Front Door
            if ($headers.Get("x-azure-ref")) {
                Write-Verbose "x-azure-ref: $($headers.Get('x-azure-ref'))"
                if ($CdnType -eq "Unknown") { $CdnType = "Azure Front Door" }
            }
            
            # CloudFront
            if ($headers.Get("X-Amz-Cf-Id")) {
                Write-Verbose "X-Amz-Cf-Id: $($headers.Get('X-Amz-Cf-Id'))"
                if ($CdnType -eq "Unknown") { $CdnType = "CloudFront" }
            }

            # Cache Status
            $headerNames = @("X-Cache", "CF-Cache-Status", "X-Proxy-Cache", "X-Cache-Status", "X-Served-By")
            foreach ($h in $headerNames) {
                $value = $headers.Get($h)
                if ($value) {
                    $hitMisses += $value
                    break
                }
            }
        }
    } catch [System.Net.WebException] {
        # Track error response code if available
        if ($_.Exception.Response) {
            $code = [int]$_.Exception.Response.StatusCode
            $responseCodes[$code] = ($responseCodes[$code] + 1) ?? 1
        }
    } finally {
        if ($resp) {
            try {
                # Get response body to ensure complete response
                $stream = $resp.GetResponseStream()
                if ($stream) {
                    $buffer = New-Object byte[] 8192
                    while ($stream.Read($buffer, 0, $buffer.Length) -gt 0) { }
                }
            }
            finally {
                $resp.Close()
            }
        }
    }
    
    $sw.Stop()
    $latency = [Math]::Round($sw.Elapsed.TotalMilliseconds, 2)
    $latencies += $latency

    # Measure TTFB
    try {
        $ttfbSw = [System.Diagnostics.Stopwatch]::StartNew()
        $req = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Url)
        $req.Method = "GET"
        $resp = $req.GetResponse()
        $ttfbSw.Stop()
        $ttfb = $ttfbSw.ElapsedMilliseconds
        # Track successful response code
        $code = [int]$resp.StatusCode
        $responseCodes[$code] = ($responseCodes[$code] + 1) ?? 1
        
        # Check for Azure ref code
        $azureRef = $resp.Headers["x-azure-ref"]
        if ($azureRef) {
            if (-not $azureRefStats.ContainsKey($azureRef)) {
                $azureRefStats[$azureRef] = @{
                    Count = 0
                    TotalLatency = 0
                    Average = 0
                }
            }
            $azureRefStats[$azureRef].Count++
            $azureRefStats[$azureRef].TotalLatency += $ttfb
            $azureRefStats[$azureRef].Average = $azureRefStats[$azureRef].TotalLatency / $azureRefStats[$azureRef].Count
        }
        
        $resp.Close()
        $ttfbs += $ttfb
    } catch [System.Net.WebException] {
        # Track error response code if available
        if ($_.Exception.Response) {
            $code = [int]$_.Exception.Response.StatusCode
            $responseCodes[$code] = ($responseCodes[$code] + 1) ?? 1
        }
        $ttfbs += $null
    }
}

Write-Progress -Activity "Running Network Diagnostics" -Completed

# Process results
$stats = @{
    SSL = Get-Statistics -values ($sslLatencies | Where-Object { $_ -ne $null } | ForEach-Object { $_.SslHandshakeTime })
    TCP = Get-Statistics -values ($sslLatencies | Where-Object { $_ -ne $null } | ForEach-Object { $_.TcpConnectionTime })
    DNS = Get-Statistics -values $dnsTimings
    Server = Get-Statistics -values $serverTimings
    Download = Get-Statistics -values $downloadTimings
    Total = Get-Statistics -values $latencies
    TTFB = Get-Statistics -values ($ttfbs | Where-Object { $_ -ne $null })
}

# Calculate complete test time (equivalent to Catchpoint's Test Time)
$testTimes = @()
for ($i = 0; $i -lt $dnsTimings.Count; $i++) {
    if ($sslLatencies[$i] -and $serverTimings[$i] -and $downloadTimings[$i]) {
        $totalTime = $dnsTimings[$i] +  # DNS Lookup
                     $sslLatencies[$i].TcpConnectionTime +  # TCP Connection
                     $sslLatencies[$i].SslHandshakeTime +  # SSL Handshake
                     $serverTimings[$i] +  # Server Processing
                     $downloadTimings[$i]  # Content Download
        $testTimes += $totalTime
    }
}
$stats["TestTime"] = Get-Statistics -values $testTimes

# Display Results
$color = if ($CdnType -eq "CloudFront") { "Green" } else { "Cyan" }
Write-Host "`nDetailed Analysis for $CdnType" -ForegroundColor $color
Write-Host "=============================" -ForegroundColor $color

Write-Host "`nSSL/TLS Connection Statistics ($Iterations runs):" -ForegroundColor Cyan
Write-Host "Protocol Version: $($sslLatencies[0].ProtocolVersion)" -ForegroundColor Magenta

Write-Host "`nSession Information:" -ForegroundColor Yellow
$initialHandshakes = ($sslLatencies | Where-Object { -not $_.IsSessionReused }).Count
$resumedSessions = ($sslLatencies | Where-Object { $_.IsSessionReused }).Count
Write-Host "  New Handshakes: $initialHandshakes" -ForegroundColor White
Write-Host "  Resumed Sessions: $resumedSessions" -ForegroundColor White
Write-Host "  Session Reuse Rate: $([Math]::Round(($resumedSessions / $Iterations) * 100, 1))%" -ForegroundColor White

# Function to format timing statistics
function Format-TimingStats {
    param($stats, $name)
    Write-Host "`n${name}:" -ForegroundColor Yellow
    Write-Host "  Average: $([Math]::Round($stats.Average,2)) ms" -ForegroundColor White
    Write-Host "  Median:  $([Math]::Round($stats.Median,2)) ms" -ForegroundColor White
    Write-Host "  StdDev:  $([Math]::Round($stats.StdDev,2)) ms" -ForegroundColor White
    Write-Host "  P95:     $([Math]::Round($stats.P95,2)) ms" -ForegroundColor White
    Write-Host "  Min/Max: $([Math]::Round($stats.Min,2))/$([Math]::Round($stats.Max,2)) ms" -ForegroundColor White
}

Format-TimingStats $stats.SSL "SSL Handshake Timing"
Format-TimingStats $stats.TCP "TCP Connection"
Format-TimingStats $stats.Cert "Certificate Validation"
Format-TimingStats $stats.DNS "DNS Resolution"
Format-TimingStats $stats.Server "Server Processing"
Format-TimingStats $stats.Download "Content Download"
Format-TimingStats $stats.TTFB "Time to First Byte"
Format-TimingStats $stats.Total "Total HTTP Response Time"

# Show file size and compression details
$sizeInfo = Get-TrueCompressedSize -Url $Url -Encoding 'gzip'
if ($sizeInfo) {
    Write-Host "`nFile Size Information:" -ForegroundColor Magenta
    Write-Host "Compressed Size: $([Math]::Round($sizeInfo.CompressedSize/1024, 2)) KB" -ForegroundColor White
    if ($sizeInfo.UncompressedSize -gt 0) {
        Write-Host "Uncompressed Size: $([Math]::Round($sizeInfo.UncompressedSize/1024, 2)) KB" -ForegroundColor White
        Write-Host "Compression Ratio: $($sizeInfo.CompressionRatio)%" -ForegroundColor White
    }
    Write-Host "Content Encoding: $($sizeInfo.ContentEncoding)" -ForegroundColor White
}

# Show HTTP response code summary
Write-Host "`nHTTP Response Codes:" -ForegroundColor Yellow
foreach ($code in $responseCodes.Keys | Sort-Object) {
    $count = $responseCodes[$code]
    $percentage = [Math]::Round(($count / ($Iterations * 2)) * 100, 1) # Times 2 because we make both HEAD and GET requests
    $color = switch ($code) {
        { $_ -ge 200 -and $_ -lt 300 } { "Green" }
        { $_ -ge 300 -and $_ -lt 400 } { "Cyan" }
        { $_ -ge 400 -and $_ -lt 500 } { "Yellow" }
        { $_ -ge 500 } { "Red" }
        default { "White" }
    }
    Write-Host "HTTP $code : $count times ($percentage%)" -ForegroundColor $color
}

# Show cache status summary
$hitCount = ($hitMisses | Where-Object { $_ -match 'HIT' }).Count
$missCount = ($hitMisses | Where-Object { $_ -match 'MISS' }).Count
Write-Host "`nCache Status:" -ForegroundColor Yellow
Write-Host "HITs: $hitCount ($([Math]::Round(($hitCount / $Iterations) * 100, 1))%)" -ForegroundColor White
Write-Host "MISSes: $missCount ($([Math]::Round(($missCount / $Iterations) * 100, 1))%)" -ForegroundColor White

# Recommendations based on statistics
# Get DNS information
Write-Host "`nDNS Information:" -ForegroundColor Cyan
$dnsInfo = Get-DnsInformation -hostname $hostname

# Display domain and IP information
Write-Host "Domain: $($dnsInfo.Domain)"
foreach ($ip in $dnsInfo.IPs) {
    Write-Host "IP: $($ip.Address)"
    if ($ip.Owner -ne "Unknown") {
        Write-Host "IP Owner: $($ip.Owner)"
    }
    if ($ip.Location -ne "Unknown") {
        Write-Host "Geo: $($ip.Location)"
    }
}

# Display DNS resolution chain
if ($dnsInfo.CNAMEs.Count -gt 0) {
    Write-Host "`nDNS Resolution Chain:" -ForegroundColor Cyan
    foreach ($cname in $dnsInfo.CNAMEs) {
        Write-Host "$($cname.From)`t$($cname.TTL)`tIN`tCNAME`t$($cname.To)"
    }
}

# Display SOA record
if ($dnsInfo.SOA) {
    Write-Host "`nSOA Record for $($dnsInfo.Domain):" -ForegroundColor Cyan
    Write-Host "Name: $($dnsInfo.SOA.Name)"
    Write-Host "NameAdministrator: $($dnsInfo.SOA.Admin)"
    Write-Host "SerialNumber: $($dnsInfo.SOA.Serial)"
    Write-Host "TimeToZoneRefresh: $($dnsInfo.SOA.Refresh)"
    Write-Host "TimeToZoneFailureRetry: $($dnsInfo.SOA.Retry)"
    Write-Host "TimeToExpiration: $($dnsInfo.SOA.Expire)"
    Write-Host "DefaultTTL: $($dnsInfo.SOA.DefaultTTL)"
}

Write-Host "`nPerformance Analysis:" -ForegroundColor Cyan

# Display average latencies and Azure ref codes
Write-Host "`nRequest Latencies:" -ForegroundColor Cyan
Write-Host "Average DNS Lookup: $([Math]::Round($stats.DNS.Average,2))ms"
Write-Host "Average SSL Handshake: $([Math]::Round($stats.SSL.Average,2))ms"
Write-Host "Average First Byte: $([Math]::Round($stats.TTFB.Average,2))ms"
Write-Host "Average Download: $([Math]::Round($stats.Download.Average,2))ms"

if ($azureRefStats.Count -gt 0) {
    Write-Host "`nAzure Front Door Reference Codes:" -ForegroundColor Cyan
    $slowestRef = $null
    $maxLatency = 0

    foreach ($ref in $azureRefStats.GetEnumerator() | Sort-Object { $_.Value.Average }) {
        Write-Host "$($ref.Key): $([Math]::Round($ref.Value.Average,2))ms average"
        if ($ref.Value.Average -gt $maxLatency) {
            $maxLatency = $ref.Value.Average
            $slowestRef = $ref.Key
        }
    }
    
    if ($slowestRef) {
        Write-Host "`nSlowest Azure Ref Code: $slowestRef ($([Math]::Round($maxLatency,2))ms)" -ForegroundColor Yellow
    }
}

if ($stats.SSL.Average -gt 100) {
    Write-Host "`n⚠️ High SSL handshake time detected ($([Math]::Round($stats.SSL.Average,2))ms)" -ForegroundColor Yellow
    Write-Host "   - Consider enabling session resumption" -ForegroundColor Gray
    Write-Host "   - Review TLS configuration and cipher suites" -ForegroundColor Gray
}

$hitRate = ($hitCount / $Iterations) * 100
if ($hitRate -lt 80) {
    Write-Host "⚠️ Low cache hit rate detected ($([Math]::Round($hitRate,1))%)" -ForegroundColor Yellow
    Write-Host "   - Review caching rules and TTL settings" -ForegroundColor Gray
    Write-Host "   - Check cache key configuration" -ForegroundColor Gray
}

if ($stats.TTFB.Average -gt 200) {
    Write-Host "⚠️ High Time to First Byte ($([Math]::Round($stats.TTFB.Average,2))ms)" -ForegroundColor Yellow
    Write-Host "   - Investigate origin response times" -ForegroundColor Gray
    Write-Host "   - Check CDN-to-origin connectivity" -ForegroundColor Gray
}

# Format the performance summary
Write-Host "`nPerformance Summary:" -ForegroundColor Cyan
$perfTable = @()

foreach ($metric in @(
    @{Name="SSL Handshake"; Data=$stats.SSL},
    @{Name="DNS Resolution"; Data=$stats.DNS},
    @{Name="TCP Connection"; Data=$stats.TCP},
    @{Name="Server Processing"; Data=$stats.Server},
    @{Name="Content Download"; Data=$stats.Download},
    @{Name="Time to First Byte"; Data=$stats.TTFB},
    @{Name="Total HTTP Response"; Data=$stats.Total},
    @{Name="Complete Test Time"; Data=$stats.TestTime}  # Equivalent to Catchpoint's Test Time
)) {
    $perfTable += [PSCustomObject]@{
        'Metric' = $metric.Name
        'Min (ms)' = [math]::Round($metric.Data.Min, 1)
        'Max (ms)' = [math]::Round($metric.Data.Max, 1)
        'Avg (ms)' = [math]::Round($metric.Data.Average, 1)
        'P95 (ms)' = [math]::Round($metric.Data.P95, 1)
        'StdDev' = [math]::Round($metric.Data.StdDev, 1)
    }
}

$perfTable | Format-Table -AutoSize

# Highlight potential performance concerns
Write-Host "Performance Insights:" -ForegroundColor Yellow
$concerns = @()

if ($stats.SSL.Average -gt 100) {
    $concerns += "• High SSL handshake time ($([Math]::Round($stats.SSL.Average,1))ms avg)"
}

if ($stats.DNS.Average -gt 50) {
    $concerns += "• Elevated DNS resolution time ($([Math]::Round($stats.DNS.Average,1))ms avg)"
}

if ($stats.TTFB.Average -gt 200) {
    $concerns += "• High Time to First Byte ($([Math]::Round($stats.TTFB.Average,1))ms avg)"
}

if ($stats.Server.StdDev -gt 100) {
    $concerns += "• Variable server processing time (StdDev: $([Math]::Round($stats.Server.StdDev,1))ms)"
}

if ($concerns.Count -gt 0) {
    $concerns | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
} else {
    Write-Host "✓ All metrics within normal ranges" -ForegroundColor Green
}

# End script without returning the stats object to avoid raw data display
$null = $null
