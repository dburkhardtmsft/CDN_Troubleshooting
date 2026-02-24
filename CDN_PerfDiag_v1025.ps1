# CDN Network Diagnostics Tool
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Url,
    
    [Parameter(Mandatory=$false)]
    [string]$CdnType = "Unknown",  # Can be "Azure Front Door", "CloudFront", or "Unknown"
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("1.2", "1.3")]
    [string]$TlsVersion,
    
    [Parameter(Mandatory=$false)]
    [switch]$DebugOutput  # Output raw timing data for analysis
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
        
        # Get CNAME chain with enhanced CloudFront support
        $domain = $hostname
        $seen = @{}
        while ($true) {
            if ($seen.ContainsKey($domain)) { break }
            $seen[$domain] = $true
            
            # Try CNAME first
            $nslookup = nslookup -type=CNAME $domain 2>$null
            $cname = $null
            $ttl = 60  # Default TTL
            
            # Process CNAME records
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
                        Type = if ($cname -match '\.cloudfront\.net$') { 'CloudFront' } 
                              elseif ($cname -match '\.azureedge\.net$') { 'Azure Front Door' }
                              else { 'Other' }
                    }
                    $domain = $cname
                }
            }
            
            # If no CNAME, try A record for final resolution
            if (-not $cname) {
                $aRecords = nslookup -type=A $domain 2>$null
                $aRecords | ForEach-Object {
                    if ($_ -match 'Name:\s+(.+)' -and $matches[1].Trim() -eq $domain) {
                        # We've hit the final A record, stop here
                        break
                    }
                }
                break
            }
        }
        
        # Get SOA record - use Resolve-DnsName for more reliable parsing
        $soaInfo = @{}
        try {
            $soaRecords = Resolve-DnsName -Name $hostname -Type SOA -ErrorAction SilentlyContinue
            if ($soaRecords) {
                foreach ($record in $soaRecords) {
                    if ($record.Type -eq 'SOA') {
                        $soaInfo.Name = $record.PrimaryServer
                        $soaInfo.Admin = $record.NameAdministrator
                        $soaInfo.Serial = $record.SerialNumber
                        $soaInfo.Refresh = $record.TimeToZoneRefresh
                        $soaInfo.Retry = $record.TimeToZoneFailureRetry
                        $soaInfo.Expire = $record.TimeToExpiration
                        $soaInfo.DefaultTTL = $record.DefaultTTL
                        break
                    }
                }
            }
        } catch {
            # Fallback to nslookup parsing if Resolve-DnsName fails
            $soa = nslookup -type=SOA $hostname 2>$null
            $soaString = $soa | Out-String
            if ($soaString -match 'primary name server = (.+)') { $soaInfo.Name = $matches[1].Trim().Trim('.') }
            if ($soaString -match 'responsible mail addr = (.+)') { $soaInfo.Admin = $matches[1].Trim().Trim('.') }
            if ($soaString -match 'serial\s*=\s*(\d+)') { $soaInfo.Serial = $matches[1] }
            if ($soaString -match 'refresh\s*=\s*(\d+)') { $soaInfo.Refresh = $matches[1] }
            if ($soaString -match 'retry\s*=\s*(\d+)') { $soaInfo.Retry = $matches[1] }
            if ($soaString -match 'expire\s*=\s*(\d+)') { $soaInfo.Expire = $matches[1] }
            if ($soaString -match 'default TTL\s*=\s*(\d+)') { $soaInfo.DefaultTTL = $matches[1] }
        }
        $dnsInfo.SOA = $soaInfo
    } catch {
        Write-Verbose "Error getting DNS information: $_"
    }
    
    return $dnsInfo
}

# Measure authoritative DNS response time (bypasses recursive resolver cache)
function Get-AuthoritativeDnsLatency {
    param([string]$Hostname)
    
    try {
        $authServer = $null
        
        # Strategy 1: Try NS records for the hostname directly
        Write-Verbose "AuthDNS: Trying NS lookup for $Hostname"
        $nsRecords = Resolve-DnsName -Name $Hostname -Type NS -DnsOnly -ErrorAction SilentlyContinue
        if ($nsRecords) {
            $authServer = ($nsRecords | Where-Object { $_.Type -eq 'NS' } | Select-Object -First 1).NameHost
            Write-Verbose "AuthDNS: Found NS from hostname: $authServer"
        }
        
        # Strategy 2: Walk up the domain hierarchy to find NS (more reliable for subdomains)
        if (-not $authServer) {
            $parts = $Hostname.Split('.')
            for ($i = 1; $i -lt $parts.Count - 1; $i++) {
                $parentDomain = ($parts[$i..($parts.Count-1)]) -join '.'
                Write-Verbose "AuthDNS: Trying NS lookup for parent domain: $parentDomain"
                $nsRecords = Resolve-DnsName -Name $parentDomain -Type NS -DnsOnly -ErrorAction SilentlyContinue
                if ($nsRecords) {
                    $nsHost = ($nsRecords | Where-Object { $_.Type -eq 'NS' } | Select-Object -First 1).NameHost
                    if ($nsHost) {
                        $authServer = $nsHost
                        Write-Verbose "AuthDNS: Found NS from parent $parentDomain : $authServer"
                        break
                    }
                }
            }
        }
        
        # Strategy 3: Fallback to SOA record
        if (-not $authServer) {
            Write-Verbose "AuthDNS: Trying SOA lookup for $Hostname"
            $soaRecords = Resolve-DnsName -Name $Hostname -Type SOA -DnsOnly -ErrorAction SilentlyContinue
            if ($soaRecords) {
                $authServer = ($soaRecords | Where-Object { $_.Type -eq 'SOA' } | Select-Object -First 1).PrimaryServer
                Write-Verbose "AuthDNS: Found NS from SOA: $authServer"
            }
        }
        
        if (-not $authServer) {
            Write-Verbose "AuthDNS: Could not find authoritative nameserver for $Hostname"
            return $null
        }
        
        # Now query the authoritative server directly
        Write-Verbose "AuthDNS: Querying $authServer for $Hostname"
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Resolve-DnsName -Name $Hostname -Server $authServer -DnsOnly -ErrorAction Stop
        $elapsed = $sw.ElapsedMilliseconds
        Write-Verbose "AuthDNS: Query succeeded in $elapsed ms"
        
        return @{
            Latency = $elapsed
            AuthServer = $authServer
        }
    }
    catch {
        Write-Verbose "AuthDNS: Query failed for $Hostname using $authServer : $_"
        return $null
    }
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

function Get-P99 {
    param([float[]]$values)
    $sorted = $values | Sort-Object
    $count = $sorted.Count
    if ($count -eq 0) { return $null }
    $index = [math]::Ceiling(0.99 * $count) - 1
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
        P99 = Get-P99 -values $values
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

# Azure Front Door POP Location Map
$script:AfdPopMap = @{
    'AKL'='Auckland'; 'AMS'='Amsterdam'; 'ATH'='Athens'; 'ATL'='Atlanta'; 'BCN'='Barcelona'
    'BER'='Berlin'; 'BJS'='Beijing'; 'BKK'='Bangkok'; 'BL'='Blue Ridge'; 'BN'='Brisbane'
    'BNA'='Nashville'; 'BNE'='Brisbane'; 'BOG'='Bogotá'; 'BOM'='Mumbai'; 'BOS'='Boston'
    'BRU'='Brussels'; 'BUD'='Budapest'; 'BUE'='Buenos Aires'; 'BUH'='Bucharest'; 'BY'='Boydton, Virginia'
    'CAI'='Cairo'; 'CBR'='Canberra'; 'CH'='Chicago'; 'CHI'='Chicago'; 'CLT'='Charlotte'
    'MWH'='Moses Lake'; 'CPH'='Copenhagen'; 'CPQ'='Campinas'; 'CO'='Quincy, WA'; 'CPT'='Cape Town'
    'CVG'='Cincinnati'; 'CWL'='Cardiff'; 'CYS'='Cheyenne'; 'DAL'='Dallas'; 'DUB'='Dublin'
    'DEL'='Delhi'; 'DFW'='Dallas/Fort Worth'; 'DM'='Des Moines'; 'DSM'='Des Moines'; 'DEN'='Denver'
    'DOH'='Doha'; 'DTT'='Detroit'; 'DUS'='Düsseldorf'; 'DXB'='Dubai'; 'EWR'='Newark'
    'FOR'='Fortaleza'; 'FRA'='Frankfurt'; 'SAO'='São Paulo'; 'GVA'='Geneva'; 'GVX'='Gävle'
    'HEL'='Helsinki'; 'HKG'='Hong Kong'; 'HNL'='Honolulu'; 'HOU'='Houston'; 'HYD'='Hyderabad'
    'IAD'='Ashburn, Virginia'; 'IST'='Istanbul'; 'JAX'='Jacksonville'; 'JGA'='Jamnagar'
    'JHB'='Johor Bahru'; 'JKT'='Jakarta'; 'JNB'='Johannesburg'; 'KUL'='Kuala Lumpur'; 'LAD'='Luanda'
    'LAS'='Las Vegas'; 'LAX'='Los Angeles'; 'LIS'='Lisbon'; 'LON'='London'; 'LOS'='Lagos'
    'MMA'='Malmo'; 'MAD'='Madrid'; 'MAN'='Manchester'; 'MEL'='Melbourne'; 'MEX'='Mexico City'
    'MIA'='Miami'; 'MIL'='Milan'; 'MNL'='Manila'; 'MRS'='Marseille'; 'MSP'='Minneapolis–Saint Paul'
    'MUC'='Munich'; 'NAG'='Nagpur'; 'NBO'='Nairobi'; 'NYC'='New York City'; 'ORD'='Chicago'
    'OSA'='Osaka'; 'OSL'='Oslo'; 'PAO'='Palo Alto'; 'PAR'='Paris'; 'PDX'='Portland, Oregon'
    'PER'='Perth'; 'PHL'='Philadelphia'; 'PHX'='Phoenix'; 'PNQ'='Pune'; 'PRG'='Prague'
    'PUS'='Busan'; 'QRO'='Querétaro City'; 'RBA'='Rabat'; 'RIO'='Rio de Janeiro'; 'ROM'='Rome'
    'SCL'='Santiago de Chile'; 'SEL'='Seoul'; 'SG'='Singapore'; 'SGN'='Ho Chi Minh City'
    'SJC'='San Jose, California'; 'SLA'='Seoul'; 'SLC'='Salt Lake City'; 'SN'='San Antonio'
    'SOF'='Sofia'; 'SEA'='Seattle'; 'STO'='Stockholm'; 'SVG'='Stavanger'; 'SYD'='Sydney'
    'TEB'='Teterboro'; 'TLV'='Tel Aviv'; 'TPE'='Taipei'; 'TYO'='Tokyo'; 'VA'='Ashburn, Virginia'
    'VIE'='Vienna'; 'WAW'='Warsaw'; 'YMQ'='Montreal'; 'YQB'='Quebec City'; 'WST'='Seattle'
    'YTO'='Toronto'; 'YVR'='Vancouver'; 'ZAG'='Zagreb'; 'ZRH'='Zurich'
}

# Function to decode AFD POP location from x-azure-ref header
function Get-AfdPopLocation {
    param([string]$AzureRef)
    
    if (-not $AzureRef) { return $null }
    
    # Extract POP code from x-azure-ref (format: timestamp-identifier where identifier contains POP code)
    # Example: 20260217T235230Z-r1f8558ffbckwg2thC1BY1xr9g...
    # The POP code is typically 2-3 chars after 'C1' or similar prefix
    
    $popCode = $null
    $location = $null
    
    # Try to find POP code patterns
    if ($AzureRef -match 'C1([A-Z]{2,3})\d') {
        $popCode = $matches[1]
    } elseif ($AzureRef -match '-[a-z0-9]+([A-Z]{2,3})\d') {
        $popCode = $matches[1]
    }
    
    if ($popCode -and $script:AfdPopMap.ContainsKey($popCode)) {
        $location = $script:AfdPopMap[$popCode]
    }
    
    return @{
        Code = $popCode
        Location = $location
    }
}

# Function to detect fallback routing
function Test-FallbackRouting {
    param([string[]]$CNAMEChain)
    
    $isFallback = $false
    $indicators = @()
    
    foreach ($cname in $CNAMEChain) {
        if ($cname -match 'fb-t-msedge\.net') {
            $isFallback = $true
            $indicators += "Fallback edge path detected: $cname"
        }
        if ($cname -match 'azurefd-t-fb-prod') {
            $isFallback = $true
            $indicators += "Fallback traffic manager: $cname"
        }
    }
    
    return @{
        IsFallback = $isFallback
        Indicators = $indicators
    }
}

# Function to calculate jitter (variation in latency)
function Get-Jitter {
    param([float[]]$values)
    
    if ($values.Count -lt 2) { return 0 }
    
    $differences = @()
    for ($i = 1; $i -lt $values.Count; $i++) {
        $differences += [Math]::Abs($values[$i] - $values[$i-1])
    }
    
    return ($differences | Measure-Object -Average).Average
}

# Function to detect outliers (values > 2 standard deviations from mean)
function Get-Outliers {
    param([float[]]$values, [int]$threshold = 2)
    
    if ($values.Count -lt 3) { return @() }
    
    $avg = ($values | Measure-Object -Average).Average
    $stdDev = [math]::Sqrt(($values | ForEach-Object { [math]::Pow($_ - $avg, 2) } | Measure-Object -Average).Average)
    
    $outliers = @()
    for ($i = 0; $i -lt $values.Count; $i++) {
        $deviation = [Math]::Abs($values[$i] - $avg)
        if ($deviation -gt ($threshold * $stdDev)) {
            $outliers += @{
                Index = $i + 1
                Value = $values[$i]
                Deviation = [Math]::Round($deviation / $stdDev, 2)
            }
        }
    }
    
    return $outliers
}

# Function to display ASCII histogram
function Show-Histogram {
    param([float[]]$values, [string]$title = "Distribution", [int]$buckets = 5)
    
    if ($values.Count -eq 0) { return }
    
    $min = ($values | Measure-Object -Minimum).Minimum
    $max = ($values | Measure-Object -Maximum).Maximum
    $range = $max - $min
    
    if ($range -eq 0) {
        Write-Host "All values are identical: $min ms" -ForegroundColor Gray
        return
    }
    
    $bucketSize = $range / $buckets
    $histogram = @{}
    
    for ($i = 0; $i -lt $buckets; $i++) {
        $bucketStart = $min + ($i * $bucketSize)
        $bucketEnd = $min + (($i + 1) * $bucketSize)
        $key = "$([Math]::Round($bucketStart,0))-$([Math]::Round($bucketEnd,0))ms"
        $histogram[$key] = @{ Count = 0; Start = $bucketStart; End = $bucketEnd; Order = $i }
    }
    
    foreach ($val in $values) {
        $bucketIndex = [Math]::Min([Math]::Floor(($val - $min) / $bucketSize), $buckets - 1)
        $bucketStart = $min + ($bucketIndex * $bucketSize)
        $bucketEnd = $min + (($bucketIndex + 1) * $bucketSize)
        $key = "$([Math]::Round($bucketStart,0))-$([Math]::Round($bucketEnd,0))ms"
        if ($histogram.ContainsKey($key)) {
            $histogram[$key].Count++
        }
    }
    
    $maxCount = ($histogram.Values | ForEach-Object { $_.Count } | Measure-Object -Maximum).Maximum
    if ($maxCount -eq 0) { $maxCount = 1 }
    
    Write-Host "`n$title`:" -ForegroundColor Cyan
    foreach ($bucket in $histogram.GetEnumerator() | Sort-Object { $_.Value.Order }) {
        $barLength = [Math]::Round(($bucket.Value.Count / $maxCount) * 30)
        $bar = '█' * $barLength
        $padding = ' ' * (15 - $bucket.Key.Length)
        Write-Host "  $($bucket.Key)$padding $bar ($($bucket.Value.Count))" -ForegroundColor White
    }
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
$authDnsTimings = @()
$authDnsServer = $null
$serverTimings = @()
$downloadTimings = @()

# Initialize tracking
$responseCodes = @{}
$azureRefStats = @{}
$httpVersions = @{}
$detectedPopLocations = @{}

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
        
        # Capture TLS details
        $tlsVersion = $sslStream.SslProtocol.ToString()
        $cipherSuite = $sslStream.CipherAlgorithm.ToString()
        $keyExchange = $sslStream.KeyExchangeAlgorithm.ToString()
        $hashAlgorithm = $sslStream.HashAlgorithm.ToString()
        
        $client.Close()
        return @{
            TcpConnectionTime = $tcpTime
            SslHandshakeTime = $sslTime
            CertValidationTime = $certTime
            TlsVersion = $tlsVersion
            CipherSuite = $cipherSuite
            KeyExchange = $keyExchange
            HashAlgorithm = $hashAlgorithm
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
        
        # Flush Windows DNS cache for accurate DNS measurement (requires admin)
        try {
            Clear-DnsClientCache -ErrorAction SilentlyContinue
        } catch {
            # Fallback for older systems or non-admin
            $null = ipconfig /flushdns 2>$null
        }
        
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        
        # Clear .NET DNS cache and prepare for fresh connection
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
    $serverTimings += $detailedTimings.ServerProcessing
    $downloadTimings += $detailedTimings.ContentDownload
    
    # Measure authoritative DNS (direct to authoritative nameserver)
    $authDnsResult = Get-AuthoritativeDnsLatency -Hostname $hostname
    if ($authDnsResult) {
        $authDnsTimings += $authDnsResult.Latency
        if (-not $authDnsServer) {
            $authDnsServer = $authDnsResult.AuthServer
        }
    }
    
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
        $req.Accept = "text/html"
        $req.ServicePoint.ConnectionLimit = 1
        $req.ServicePoint.UseNagleAlgorithm = $false
        $resp = $req.GetResponse()
        # Track successful response code
        $code = [int]$resp.StatusCode
        if ($responseCodes.ContainsKey($code)) {
            $responseCodes[$code] = $responseCodes[$code] + 1
        } else {
            $responseCodes[$code] = 1
        }
        
        # Track HTTP version
        $httpVer = $resp.ProtocolVersion.ToString()
        if ($httpVersions.ContainsKey($httpVer)) {
            $httpVersions[$httpVer]++
        } else {
            $httpVersions[$httpVer] = 1
        }

        # Check for CDN-specific headers if we got a response
        $headers = $resp.Headers
        if ($headers) {
            # Azure Front Door
            if ($headers.Get("x-azure-ref")) {
                $azureRef = $headers.Get('x-azure-ref')
                Write-Verbose "x-azure-ref: $azureRef"
                if ($CdnType -eq "Unknown") { $CdnType = "Azure Front Door" }
                
                # Decode and track POP location
                $popInfo = Get-AfdPopLocation -AzureRef $azureRef
                if ($popInfo.Code) {
                    if ($detectedPopLocations.ContainsKey($popInfo.Code)) {
                        $detectedPopLocations[$popInfo.Code].Count++
                    } else {
                        $detectedPopLocations[$popInfo.Code] = @{
                            Count = 1
                            Location = $popInfo.Location
                        }
                    }
                }
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
            if ($responseCodes.ContainsKey($code)) {
                $responseCodes[$code] = $responseCodes[$code] + 1
            } else {
                $responseCodes[$code] = 1
            }
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
        if ($responseCodes.ContainsKey($code)) {
            $responseCodes[$code] = $responseCodes[$code] + 1
        } else {
            $responseCodes[$code] = 1
        }
        
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
            if ($responseCodes.ContainsKey($code)) {
                $responseCodes[$code] = $responseCodes[$code] + 1
            } else {
                $responseCodes[$code] = 1
            }
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
    AuthDNS = if ($authDnsTimings.Count -gt 0) { Get-Statistics -values $authDnsTimings } else { $null }
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

# Calculate jitter for key metrics
$ttfbJitter = Get-Jitter -values ($ttfbs | Where-Object { $_ -ne $null })
$latencyJitter = Get-Jitter -values $latencies

# Detect outliers
$ttfbOutliers = Get-Outliers -values ($ttfbs | Where-Object { $_ -ne $null })
$latencyOutliers = Get-Outliers -values $latencies

# Connection Reuse Test - measure persistent connection performance
Write-Host "`nTesting connection reuse (Keep-Alive)..." -ForegroundColor Yellow
$connectionReuseResults = @{
    FirstRequestTime = 0
    SubsequentRequests = @()
    ConnectionKeptAlive = $false
    AvgReuseTime = 0
    ConnectionDroppedAfter = 0
}

try {
    # Create a single HttpClient that maintains connection
    Add-Type -AssemblyName System.Net.Http
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.UseDefaultCredentials = $false
    $httpClient = New-Object System.Net.Http.HttpClient($handler)
    $httpClient.DefaultRequestHeaders.Add("Connection", "keep-alive")
    $httpClient.Timeout = [TimeSpan]::FromSeconds(30)
    
    # Make 10 rapid requests over the same connection
    $reuseTimings = @()
    for ($i = 1; $i -le 10; $i++) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $response = $httpClient.GetAsync($Url).Result
        $elapsed = $sw.ElapsedMilliseconds
        $reuseTimings += $elapsed
        
        if ($i -eq 1) {
            $connectionReuseResults.FirstRequestTime = $elapsed
        }
        
        # Small delay to simulate realistic usage
        Start-Sleep -Milliseconds 50
    }
    
    $httpClient.Dispose()
    
    # Analyze results
    $connectionReuseResults.SubsequentRequests = $reuseTimings | Select-Object -Skip 1
    if ($connectionReuseResults.SubsequentRequests.Count -gt 0) {
        $connectionReuseResults.AvgReuseTime = [Math]::Round(($connectionReuseResults.SubsequentRequests | Measure-Object -Average).Average, 2)
        
        # If subsequent requests are significantly faster than first, connection is being reused
        $firstReq = $connectionReuseResults.FirstRequestTime
        $avgSubseq = $connectionReuseResults.AvgReuseTime
        $connectionReuseResults.ConnectionKeptAlive = ($avgSubseq -lt ($firstReq * 0.8))
        
        # Check if any request took much longer (connection dropped)
        $threshold = $avgSubseq * 2
        $droppedAt = 0
        foreach ($time in $connectionReuseResults.SubsequentRequests) {
            $droppedAt++
            if ($time -gt $threshold -and $time -gt 100) {
                $connectionReuseResults.ConnectionDroppedAfter = $droppedAt
                break
            }
        }
    }
}
catch {
    Write-Verbose "Connection reuse test failed: $_"
}

# Display Results
$color = if ($CdnType -eq "CloudFront") { "Green" } else { "Cyan" }
Write-Host "`nDetailed Analysis for $CdnType" -ForegroundColor $color
Write-Host "=============================" -ForegroundColor $color

# TLS/SSL Details (Enhancement #7)
Write-Host "`nSSL/TLS Connection Statistics ($Iterations runs):" -ForegroundColor Cyan
if ($sslLatencies.Count -gt 0 -and $sslLatencies[0]) {
    Write-Host "TLS Version: $($sslLatencies[0].TlsVersion)" -ForegroundColor Magenta
    Write-Host "Cipher Algorithm: $($sslLatencies[0].CipherSuite)" -ForegroundColor Magenta
    Write-Host "Key Exchange: $($sslLatencies[0].KeyExchange)" -ForegroundColor Magenta
    Write-Host "Hash Algorithm: $($sslLatencies[0].HashAlgorithm)" -ForegroundColor Magenta
}

# HTTP Version Detection (Enhancement #8)
if ($httpVersions.Count -gt 0) {
    Write-Host "`nHTTP Protocol Versions:" -ForegroundColor Cyan
    foreach ($ver in $httpVersions.GetEnumerator()) {
        Write-Host "  HTTP/$($ver.Key): $($ver.Value) requests" -ForegroundColor White
    }
}

Write-Host "`nSession Information:" -ForegroundColor Yellow
$initialHandshakes = ($sslLatencies | Where-Object { -not $_.IsSessionReused }).Count
$resumedSessions = ($sslLatencies | Where-Object { $_.IsSessionReused }).Count
Write-Host "  New Handshakes: $initialHandshakes" -ForegroundColor White
Write-Host "  Resumed Sessions: $resumedSessions" -ForegroundColor White
$sessionReuseRate = [Math]::Round(($resumedSessions / $Iterations) * 100, 1)
Write-Host "  Session Reuse Rate: $sessionReuseRate%" -ForegroundColor White

# Connection Reuse Analysis (Keep-Alive Test)
Write-Host "`n--- Connection Reuse (Keep-Alive) Test ---" -ForegroundColor Cyan
if ($connectionReuseResults.FirstRequestTime -gt 0) {
    Write-Host "First Request (cold):     $($connectionReuseResults.FirstRequestTime) ms" -ForegroundColor White
    Write-Host "Subsequent Avg (warm):    $($connectionReuseResults.AvgReuseTime) ms" -ForegroundColor White
    
    if ($connectionReuseResults.SubsequentRequests.Count -gt 0) {
        $savings = $connectionReuseResults.FirstRequestTime - $connectionReuseResults.AvgReuseTime
        $savingsPct = [Math]::Round(($savings / $connectionReuseResults.FirstRequestTime) * 100, 0)
        
        if ($connectionReuseResults.ConnectionKeptAlive) {
            Write-Host "Connection Reuse:         " -NoNewline -ForegroundColor White
            Write-Host "YES" -ForegroundColor Green
            Write-Host "Latency Savings:          $([Math]::Round($savings, 0)) ms ($savingsPct% faster)" -ForegroundColor Green
        } else {
            Write-Host "Connection Reuse:         " -NoNewline -ForegroundColor White
            Write-Host "POOR/NO" -ForegroundColor Red
            Write-Host "  [!] CDN may not be honoring Keep-Alive or connections are being reset" -ForegroundColor Yellow
        }
        
        if ($connectionReuseResults.ConnectionDroppedAfter -gt 0) {
            Write-Host "Connection Dropped After: Request #$($connectionReuseResults.ConnectionDroppedAfter + 1)" -ForegroundColor Yellow
            Write-Host "  [!] Connection was reset mid-test - may indicate aggressive idle timeout" -ForegroundColor Yellow
        }
        
        # Show all 10 request times
        Write-Host "Request Times (10 rapid requests over same connection):" -ForegroundColor Gray
        $allTimes = @($connectionReuseResults.FirstRequestTime) + $connectionReuseResults.SubsequentRequests
        Write-Host "  $($allTimes -join 'ms, ')ms" -ForegroundColor Gray
    }
} else {
    Write-Host "Connection reuse test skipped or failed" -ForegroundColor Gray
}

# Session Reuse Alert (Enhancement #6)
if ($sessionReuseRate -eq 0 -and -not $connectionReuseResults.ConnectionKeptAlive) {
    Write-Host "`n  [!] No session reuse detected" -ForegroundColor Yellow
    Write-Host "      Recommendation: Enable HTTP Keep-Alive and connection pooling" -ForegroundColor Gray
    Write-Host "      This can reduce latency by ~50-70ms per request" -ForegroundColor Gray
}

# First Request vs Steady State Analysis (Enhancement #4)
if ($ttfbs.Count -gt 1) {
    $firstRequestTtfb = $ttfbs[0]
    $steadyStateTtfbs = $ttfbs | Select-Object -Skip 1
    $steadyStateAvg = ($steadyStateTtfbs | Where-Object { $_ -ne $null } | Measure-Object -Average).Average
    
    Write-Host "`n--- First Request vs Steady State ---" -ForegroundColor Cyan
    Write-Host "First Request TTFB:  $([Math]::Round($firstRequestTtfb, 2)) ms" -ForegroundColor White
    Write-Host "Steady State Avg:    $([Math]::Round($steadyStateAvg, 2)) ms (requests 2-$($Iterations))" -ForegroundColor White
    
    if ($firstRequestTtfb -gt ($steadyStateAvg * 1.5)) {
        $overhead = $firstRequestTtfb - $steadyStateAvg
        $overheadPct = [Math]::Round(($overhead / $steadyStateAvg) * 100, 0)
        Write-Host "Cold Start Overhead: +$([Math]::Round($overhead, 0)) ms ($overheadPct% slower)" -ForegroundColor Yellow
        Write-Host "  This is normal - first request includes full TCP/TLS handshake" -ForegroundColor Gray
    }
}

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

# Jitter Analysis (Enhancement #9)
Write-Host "`n--- Latency Jitter Analysis ---" -ForegroundColor Cyan
Write-Host "TTFB Jitter:     $([Math]::Round($ttfbJitter, 2)) ms (avg variation between consecutive requests)" -ForegroundColor White
Write-Host "Response Jitter: $([Math]::Round($latencyJitter, 2)) ms" -ForegroundColor White
if ($ttfbJitter -gt 20) {
    Write-Host "  [!] High jitter detected - may indicate network instability or variable server load" -ForegroundColor Yellow
}

# Outlier Detection (Enhancement #5)
if ($ttfbOutliers.Count -gt 0 -or $latencyOutliers.Count -gt 0) {
    Write-Host "`n--- Outlier Analysis ---" -ForegroundColor Cyan
    Write-Host "[!] $($ttfbOutliers.Count + $latencyOutliers.Count) outlier(s) detected (>2 standard deviations from mean):" -ForegroundColor Yellow
    foreach ($outlier in $ttfbOutliers) {
        Write-Host "  Request #$($outlier.Index): $([Math]::Round($outlier.Value, 0)) ms TTFB ($($outlier.Deviation)σ from mean)" -ForegroundColor Yellow
    }
}

# Latency Histogram (Enhancement #10)
Show-Histogram -values ($ttfbs | Where-Object { $_ -ne $null }) -title "TTFB Distribution" -buckets 5

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
    
    # Fallback Routing Detection (Enhancement #3)
    $cnameChain = $dnsInfo.CNAMEs | ForEach-Object { $_.To }
    $fallbackCheck = Test-FallbackRouting -CNAMEChain $cnameChain
    if ($fallbackCheck.IsFallback) {
        Write-Host "`n[!] Fallback Routing Detected:" -ForegroundColor Yellow
        foreach ($indicator in $fallbackCheck.Indicators) {
            Write-Host "    $indicator" -ForegroundColor Yellow
        }
        Write-Host "    This may indicate primary edge path is unavailable or deprioritized" -ForegroundColor Gray
    }
}

# Display SOA record
if ($dnsInfo.SOA -and $dnsInfo.SOA.Name) {
    Write-Host "`nSOA Record for $($dnsInfo.Domain):" -ForegroundColor Cyan
    Write-Host "Name: $($dnsInfo.SOA.Name)"
    if ($dnsInfo.SOA.Admin) { Write-Host "NameAdministrator: $($dnsInfo.SOA.Admin)" }
    if ($dnsInfo.SOA.Serial) { Write-Host "SerialNumber: $($dnsInfo.SOA.Serial)" }
    if ($dnsInfo.SOA.Refresh) { Write-Host "TimeToZoneRefresh: $($dnsInfo.SOA.Refresh)" }
    if ($dnsInfo.SOA.Retry) { Write-Host "TimeToZoneFailureRetry: $($dnsInfo.SOA.Retry)" }
    if ($dnsInfo.SOA.Expire) { Write-Host "TimeToExpiration: $($dnsInfo.SOA.Expire)" }
    if ($dnsInfo.SOA.DefaultTTL) { Write-Host "DefaultTTL: $($dnsInfo.SOA.DefaultTTL)" }
}

Write-Host "`nPerformance Analysis:" -ForegroundColor Cyan

# AFD POP Location Summary (Enhancement #2)
if ($detectedPopLocations.Count -gt 0) {
    Write-Host "`n--- Azure Front Door POP Locations ---" -ForegroundColor Cyan
    foreach ($pop in $detectedPopLocations.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending) {
        $location = if ($pop.Value.Location) { $pop.Value.Location } else { "Unknown" }
        Write-Host "  $($pop.Key) ($location): $($pop.Value.Count) requests" -ForegroundColor White
    }
}

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
        # Decode POP location for each ref
        $popInfo = Get-AfdPopLocation -AzureRef $ref.Key
        $popDisplay = if ($popInfo.Location) { " [$($popInfo.Code) - $($popInfo.Location)]" } else { "" }
        Write-Host "$($ref.Key): $([Math]::Round($ref.Value.Average,2))ms average$popDisplay"
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
if ($authDnsServer) {
    Write-Host "(Authoritative DNS Server: $authDnsServer)" -ForegroundColor Gray
}
$perfTable = @()

# Build metrics list, conditionally including Auth DNS if available
$metricsList = @(
    @{Name="SSL Handshake"; Data=$stats.SSL},
    @{Name="DNS Resolution"; Data=$stats.DNS}
)
if ($stats.AuthDNS) {
    $metricsList += @{Name="  Auth DNS (direct)"; Data=$stats.AuthDNS}
}
$metricsList += @(
    @{Name="TCP Connection"; Data=$stats.TCP},
    @{Name="Server Processing"; Data=$stats.Server},
    @{Name="Content Download"; Data=$stats.Download},
    @{Name="Time to First Byte"; Data=$stats.TTFB},
    @{Name="Total HTTP Response"; Data=$stats.Total},
    @{Name="Complete Test Time"; Data=$stats.TestTime}
)

foreach ($metric in $metricsList) {
    if ($metric.Data) {
        $perfTable += [PSCustomObject]@{
            'Metric' = $metric.Name
            'Min (ms)' = [math]::Round($metric.Data.Min, 1)
            'Max (ms)' = [math]::Round($metric.Data.Max, 1)
            'Avg (ms)' = [math]::Round($metric.Data.Average, 1)
            'P95 (ms)' = [math]::Round($metric.Data.P95, 1)
            'P99 (ms)' = [math]::Round($metric.Data.P99, 1)
            'StdDev' = [math]::Round($metric.Data.StdDev, 1)
        }
    }
}

$perfTable | Format-Table -AutoSize

# Connection Reuse Summary
if ($connectionReuseResults.FirstRequestTime -gt 0 -and $connectionReuseResults.SubsequentRequests.Count -gt 0) {
    Write-Host "`nConnection Reuse Summary:" -ForegroundColor Cyan
    $reuseStatus = if ($connectionReuseResults.ConnectionKeptAlive) { "GOOD" } else { "POOR" }
    $reuseColor = if ($connectionReuseResults.ConnectionKeptAlive) { "Green" } else { "Red" }
    $savings = $connectionReuseResults.FirstRequestTime - $connectionReuseResults.AvgReuseTime
    $savingsPct = if ($connectionReuseResults.FirstRequestTime -gt 0) { [Math]::Round(($savings / $connectionReuseResults.FirstRequestTime) * 100, 0) } else { 0 }
    
    Write-Host "Keep-Alive Status: " -NoNewline
    Write-Host $reuseStatus -ForegroundColor $reuseColor
    Write-Host "Cold Request: $($connectionReuseResults.FirstRequestTime)ms | Warm Avg: $($connectionReuseResults.AvgReuseTime)ms | Savings: ${savingsPct}%" -ForegroundColor White
}

# Debug output for raw timing analysis
if ($DebugOutput) {
    Write-Host ""
    Write-Host "==================== DEBUG OUTPUT ===================" -ForegroundColor Magenta
    Write-Host "Raw timing data for analysis (copy everything below):" -ForegroundColor Magenta
    Write-Host "======================================================" -ForegroundColor Magenta
    Write-Host ""
    
    Write-Host "URL: $Url" -ForegroundColor Cyan
    Write-Host "CDN Type: $CdnType" -ForegroundColor Cyan
    Write-Host "Iterations: $Iterations" -ForegroundColor Cyan
    Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "--- RAW TIMING ARRAYS (ms) ---" -ForegroundColor Yellow
    
    # Extract numeric arrays from the actual data sources used by statistics
    $sslTimingsNumeric = $sslLatencies | Where-Object { $_ -ne $null } | ForEach-Object { $_.SslHandshakeTime }
    $tcpTimingsFromSSL = $sslLatencies | Where-Object { $_ -ne $null } | ForEach-Object { $_.TcpConnectionTime }
    $ttfbsNumeric = $ttfbs | Where-Object { $_ -ne $null }
    
    Write-Host "DNS_TIMINGS: $($dnsTimings -join ', ')" -ForegroundColor White
    Write-Host ""
    if ($authDnsTimings.Count -gt 0) {
        Write-Host "AUTH_DNS_TIMINGS: $($authDnsTimings -join ', ')" -ForegroundColor White
        Write-Host "AUTH_DNS_SERVER: $authDnsServer" -ForegroundColor Gray
        Write-Host ""
    }
    Write-Host "TCP_TIMINGS: $($tcpTimingsFromSSL -join ', ')" -ForegroundColor White
    Write-Host ""
    Write-Host "SSL_TIMINGS: $($sslTimingsNumeric -join ', ')" -ForegroundColor White
    Write-Host ""
    Write-Host "SERVER_TIMINGS: $($serverTimings -join ', ')" -ForegroundColor White
    Write-Host ""
    Write-Host "DOWNLOAD_TIMINGS: $($downloadTimings -join ', ')" -ForegroundColor White
    Write-Host ""
    Write-Host "TTFB_TIMINGS: $($ttfbsNumeric -join ', ')" -ForegroundColor White
    Write-Host ""
    Write-Host "TOTAL_LATENCIES: $($latencies -join ', ')" -ForegroundColor White
    Write-Host ""
    
    Write-Host "--- CALCULATED STATISTICS ---" -ForegroundColor Yellow
    $debugStats = @(
        @{Name='DNS'; Data=$stats.DNS; Raw=$dnsTimings}
    )
    if ($stats.AuthDNS) {
        $debugStats += @{Name='AuthDNS'; Data=$stats.AuthDNS; Raw=$authDnsTimings}
    }
    $debugStats += @(
        @{Name='TCP'; Data=$stats.TCP; Raw=$tcpTimingsFromSSL},
        @{Name='SSL'; Data=$stats.SSL; Raw=$sslTimingsNumeric},
        @{Name='Server'; Data=$stats.Server; Raw=$serverTimings},
        @{Name='Download'; Data=$stats.Download; Raw=$downloadTimings},
        @{Name='TTFB'; Data=$stats.TTFB; Raw=$ttfbsNumeric},
        @{Name='Total'; Data=$stats.Total; Raw=$latencies}
    )
    
    foreach ($item in $debugStats) {
        $sorted = $item.Raw | Sort-Object
        Write-Host "$($item.Name):" -ForegroundColor Cyan
        Write-Host "  Count: $($item.Data.Count)" -ForegroundColor White
        Write-Host "  Min: $([math]::Round($item.Data.Min, 2)), Max: $([math]::Round($item.Data.Max, 2))" -ForegroundColor White
        Write-Host "  Avg: $([math]::Round($item.Data.Average, 2)), Median: $([math]::Round($item.Data.Median, 2))" -ForegroundColor White
        Write-Host "  StdDev: $([math]::Round($item.Data.StdDev, 2))" -ForegroundColor White
        Write-Host "  P95: $([math]::Round($item.Data.P95, 2)), P99: $([math]::Round($item.Data.P99, 2))" -ForegroundColor White
        Write-Host "  P95 Index: $([math]::Ceiling(0.95 * $item.Data.Count) - 1), P99 Index: $([math]::Ceiling(0.99 * $item.Data.Count) - 1)" -ForegroundColor Gray
        if ($sorted.Count -ge 5) {
            Write-Host "  Top 5 values: $($sorted[-5..-1] -join ', ')" -ForegroundColor Gray
        }
        Write-Host ""
    }
    
    Write-Host "=================== END DEBUG ===================" -ForegroundColor Magenta
    Write-Host ""
}

# Highlight potential performance concerns
Write-Host "Performance Insights:" -ForegroundColor Yellow
$concerns = @()

if ($stats.SSL.Average -gt 100) {
    $concerns += "* High SSL handshake time ($([Math]::Round($stats.SSL.Average,1))ms avg)"
}

if ($stats.DNS.Average -gt 50) {
    $concerns += "* Elevated DNS resolution time ($([Math]::Round($stats.DNS.Average,1))ms avg)"
}

if ($stats.TCP.Max -gt 500) {
    $concerns += "* Very high TCP connection max time ($([Math]::Round($stats.TCP.Max,1))ms)"
}

if ($stats.TCP.StdDev -gt 50) {
    $concerns += "* Variable TCP connection time (StdDev: $([Math]::Round($stats.TCP.StdDev,1))ms)"
}

if ($stats.TTFB.Max -gt 200) {
    $concerns += "* High Time to First Byte max ($([Math]::Round($stats.TTFB.Max,1))ms)"
}

if ($stats.TTFB.Average -gt 100) {
    $concerns += "* Elevated Time to First Byte average ($([Math]::Round($stats.TTFB.Average,1))ms avg)"
}

if ($stats.Server.StdDev -gt 20) {
    $concerns += "* Variable server processing time (StdDev: $([Math]::Round($stats.Server.StdDev,1))ms)"
}

if ($stats.Total.Max -gt 200) {
    $concerns += "* High total response time max ($([Math]::Round($stats.Total.Max,1))ms)"
}

if ($stats.TestTime.Max -gt 1000) {
    $concerns += "* Very high complete test time max ($([Math]::Round($stats.TestTime.Max,1))ms)"
}

if ($concerns.Count -gt 0) {
    $concerns | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
} else {
    Write-Host "[OK] All metrics within normal ranges" -ForegroundColor Green
}

# End script without returning the stats object to avoid raw data display
$null = $null
