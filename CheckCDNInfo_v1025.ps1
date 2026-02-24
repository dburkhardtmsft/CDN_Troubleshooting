param(
    [Parameter(Mandatory=$true)]
    [string]$Url,
    [switch]$SkipGeo,
    [string]$SubscriptionKey
)

# Prompt for subscription key if not provided
if (-not $SubscriptionKey) {
    $needsKey = Read-Host "Does this URL require an API subscription key? (y/n)"
    if ($needsKey -eq 'y' -or $needsKey -eq 'Y') {
        $SubscriptionKey = Read-Host "Enter the ocp-apim-subscription-key value"
    }
}

# Store subscription key at script level for use in functions
$script:SubscriptionKey = $SubscriptionKey

# Global cache for geo lookups to avoid duplicate API calls
$script:GeoCache = @{}

# CDN Detection Patterns
$script:CDNPatterns = @{
    'Akamai' = @('akamai', 'akamaized', 'akamaitechnologies', 'akamaiedge', 'akamaicdn', 'akstat', 'akafms', 'edgekey.net', 'edgesuite.net')
    'Cloudflare' = @('cloudflare', 'cf-ray', 'cf-cache-status', 'cdn-cgi', 'cloudflare-nginx', '__cf_bm', '__cfduid')
    'Fastly' = @('fastly', 'fastly.net', 'x-served-by', 'x-fastly-request-id', 'x-cache:.*fastly', 'fastly-restarts', 'fastly-debug')
    'Amazon CloudFront' = @('cloudfront', 'cloudfront.net', 'x-amz-cf-id', 'x-amz-cf-pop')
    'Azure Front Door' = @('azurefd.net') # Only the most specific Azure Front Door domain
    'Azure CDN' = @('azureedge.net') # Separate Azure CDN from Front Door - removed overly broad header patterns
    'Google CDN' = @('googleapis.com', 'googleusercontent.com', 'googlehosted', 'x-goog-meta', 'x-goog-generation', 'x-goog-storage-class', '1e100.net')
    'StackPath' = @('stackpath', 'highwinds', 'hwcdn', 'x-hw', 'stackpathdns')
    'KeyCDN' = @('keycdn', 'x-keycdn', 'keycdn.com')
    'CDN77' = @('cdn77', 'cdn77.com', 'x-cdn77')
    'BunnyCDN' = @('bunnycdn', 'b-cdn.net', 'x-bunnycdn')
    'ChinaCache' = @('chinacache', 'ccgslb.com', 'ccgslb.net')
    'G-Core Labs' = @('gcore', 'gcorelabs', 'gcdn.co', 'gcdn.com')
    'CDNetworks' = @('cdnetworks', 'cdngc.net', 'panthercdn.com')
    'CacheFly' = @('cachefly', 'cachefly.net')
    'Limelight' = @('llnw', 'limelight', 'limelight.com', 'llnwd.net')
    'Quantil' = @('quantil', 'quantil.com', 'quantil.net')
    'Verizon Edgecast' = @('edgecast', 'edgecastcdn.net', 'msecnd.net')
    'Alibaba Cloud CDN' = @('aliyun', 'alibaba', 'cdn.aliyun.com', 'cdn.alibaba.com')
    'Tencent Cloud CDN' = @('tencent', 'cdn.tencent-cloud.net', 'x-tencent')
    'Netflix Open Connect' = @('x-netflix', 'netflix-openconnect', 'openconnect', 'nflxvideo.net', 'netflix.com')
    'CDNJS' = @('cdnjs', 'cdnjs.cloudflare.com')
    'jsDelivr' = @('jsdelivr', 'cdn.jsdelivr.net')
}

# DDoS Protection Detection Patterns
$script:DDoSPatterns = @{
    'Cloudflare' = @('cf-mitigated', 'cf-ray.*ddos', 'cloudflare-ddos', 'cf-bot-protection')
    'Incapsula' = @('incap', 'incapsula', 'x-iinfo', 'incap_ses', 'visid_incap', 'incapsula-ddos')
    'Akamai Prolexic' = @('prolexic', 'akamai-prolexic', 'x-akamai-prolexic', 'akamai-origin-hop', 'prolexic-ddos')
    'Akamai DDoS Protection' = @('akamai.*ddos', 'akamai.*protection')
    'AWS Shield' = @('aws-shield', 'x-aws-shield', 'x-amzn-shield')
    'Azure DDoS Protection' = @('azure-ddos', 'x-azure-ddos', 'azure-ddos-protection')
    'Sucuri' = @('sucuri', 'x-sucuri', 'sucuri-cache', 'sucuri-ddos')
    'Radware' = @('radware', 'x-radware', 'radware-alteon', 'radware-ddos')
    'F5 Silverline' = @('silverline', 'x-f5-silverline', 'f5-silverline', 'x-f5-ddos', 'f5 networks')
    'Neustar UltraDDoS' = @('neustar', 'ultradns', 'x-neustar', 'neustar-ddos')
    'Verisign DDoS Protection' = @('verisign', 'x-verisign-ddos')
    'Arbor Networks' = @('arbor', 'x-arbor', 'arbor-sightline', 'arbor-ddos')
    'Nexusguard' = @('nexusguard', 'x-nexusguard')
    'Deflect' = @('deflect', 'x-deflect')
    'Project Shield' = @('project-shield', 'projectshield')
    'Imperva' = @('imperva', 'x-imperva', 'imperva-session')
    'Fastly' = @('fastly-ddos', 'x-fastly-ddos', 'fastly-shield')
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

# Recommended Security Headers
$script:RecommendedSecurityHeaders = @(
    @{ Name = 'Strict-Transport-Security'; Description = 'HSTS - Forces HTTPS connections'; Severity = 'High' },
    @{ Name = 'Content-Security-Policy'; Description = 'CSP - Prevents XSS and injection attacks'; Severity = 'High' },
    @{ Name = 'X-Content-Type-Options'; Description = 'Prevents MIME type sniffing'; Severity = 'Medium' },
    @{ Name = 'X-Frame-Options'; Description = 'Prevents clickjacking attacks'; Severity = 'Medium' },
    @{ Name = 'X-XSS-Protection'; Description = 'Legacy XSS protection (deprecated but still useful)'; Severity = 'Low' },
    @{ Name = 'Referrer-Policy'; Description = 'Controls referrer information sent'; Severity = 'Low' },
    @{ Name = 'Permissions-Policy'; Description = 'Controls browser feature permissions'; Severity = 'Low' }
)

# Origin Type Detection Patterns
$script:OriginPatterns = @{
    'AWS' = @(
        @{ Pattern = '\.amazonaws\.com$'; Type = 'AWS S3/CloudFront'; Category = 'Cloud Storage' },
        @{ Pattern = '\.aws\.dev$'; Type = 'AWS'; Category = 'Cloud Platform' },
        @{ Pattern = '\.awsapps\.com$'; Type = 'AWS Apps'; Category = 'Cloud Platform' },
        @{ Pattern = 'ec2.*\.amazonaws\.com$'; Type = 'AWS EC2'; Category = 'Cloud Compute' },
        @{ Pattern = 'elasticbeanstalk\.com$'; Type = 'AWS Elastic Beanstalk'; Category = 'Cloud Platform' },
        @{ Pattern = 'cloudfront\.net$'; Type = 'AWS CloudFront'; Category = 'CDN' },
        @{ Pattern = 'elb\.amazonaws\.com$'; Type = 'AWS Load Balancer'; Category = 'Cloud Infrastructure' }
    )
    'Azure' = @(
        @{ Pattern = '\.azurewebsites\.net$'; Type = 'Azure App Service'; Category = 'Cloud Platform' },
        @{ Pattern = '\.cloudapp\.azure\.com$'; Type = 'Azure Virtual Machine'; Category = 'Cloud Compute' },
        @{ Pattern = '\.azurefd\.net$'; Type = 'Azure Front Door'; Category = 'CDN' },
        @{ Pattern = '\.azureedge\.net$'; Type = 'Azure CDN'; Category = 'CDN' },
        @{ Pattern = '\.blob\.core\.windows\.net$'; Type = 'Azure Blob Storage'; Category = 'Cloud Storage' },
        @{ Pattern = '\.database\.windows\.net$'; Type = 'Azure SQL Database'; Category = 'Cloud Database' },
        @{ Pattern = '\.servicebus\.windows\.net$'; Type = 'Azure Service Bus'; Category = 'Cloud Messaging' }
    )
    'Google Cloud' = @(
        @{ Pattern = '\.appspot\.com$'; Type = 'Google App Engine'; Category = 'Cloud Platform' },
        @{ Pattern = '\.googleusercontent\.com$'; Type = 'Google Cloud Storage'; Category = 'Cloud Storage' },
        @{ Pattern = '\.googleapis\.com$'; Type = 'Google APIs'; Category = 'Cloud APIs' },
        @{ Pattern = '\.cloudfunctions\.net$'; Type = 'Google Cloud Functions'; Category = 'Serverless' },
        @{ Pattern = '\.run\.app$'; Type = 'Google Cloud Run'; Category = 'Container Platform' },
        @{ Pattern = '\.web\.app$'; Type = 'Firebase Hosting'; Category = 'Static Hosting' },
        @{ Pattern = '\.firebaseapp\.com$'; Type = 'Firebase Hosting'; Category = 'Static Hosting' }
    )
    'Vercel' = @(
        @{ Pattern = '\.vercel\.app$'; Type = 'Vercel'; Category = 'Static Hosting' },
        @{ Pattern = '\.now\.sh$'; Type = 'Vercel (Legacy)'; Category = 'Static Hosting' },
        @{ Pattern = 'vercel\.com$'; Type = 'Vercel'; Category = 'Static Hosting' }
    )
    'Netlify' = @(
        @{ Pattern = '\.netlify\.app$'; Type = 'Netlify'; Category = 'Static Hosting' },
        @{ Pattern = '\.netlify\.com$'; Type = 'Netlify'; Category = 'Static Hosting' }
    )
    'GitHub Pages' = @(
        @{ Pattern = '\.github\.io$'; Type = 'GitHub Pages'; Category = 'Static Hosting' }
    )
    'Heroku' = @(
        @{ Pattern = '\.herokuapp\.com$'; Type = 'Heroku'; Category = 'Cloud Platform' },
        @{ Pattern = '\.herokucdn\.com$'; Type = 'Heroku CDN'; Category = 'CDN' }
    )
    'DigitalOcean' = @(
        @{ Pattern = '\.digitaloceanspaces\.com$'; Type = 'DigitalOcean Spaces'; Category = 'Cloud Storage' },
        @{ Pattern = '\.ondigitalocean\.app$'; Type = 'DigitalOcean App Platform'; Category = 'Cloud Platform' }
    )
    'Shopify' = @(
        @{ Pattern = '\.myshopify\.com$'; Type = 'Shopify'; Category = 'E-commerce Platform' },
        @{ Pattern = '\.shopifycdn\.com$'; Type = 'Shopify CDN'; Category = 'CDN' }
    )
    'WordPress' = @(
        @{ Pattern = '\.wordpress\.com$'; Type = 'WordPress.com'; Category = 'CMS Platform' },
        @{ Pattern = '\.wp\.com$'; Type = 'WordPress.com'; Category = 'CMS Platform' },
        @{ Pattern = '\.wpengine\.com$'; Type = 'WP Engine'; Category = 'Managed WordPress' }
    )
    'Squarespace' = @(
        @{ Pattern = '\.squarespace\.com$'; Type = 'Squarespace'; Category = 'Website Builder' }
    )
    'Wix' = @(
        @{ Pattern = '\.wixsite\.com$'; Type = 'Wix'; Category = 'Website Builder' },
        @{ Pattern = '\.wix\.com$'; Type = 'Wix'; Category = 'Website Builder' }
    )
    'Medium' = @(
        @{ Pattern = '\.medium\.com$'; Type = 'Medium'; Category = 'Publishing Platform' }
    )
    'Cloudflare' = @(
        @{ Pattern = '\.pages\.dev$'; Type = 'Cloudflare Pages'; Category = 'Static Hosting' },
        @{ Pattern = '\.workers\.dev$'; Type = 'Cloudflare Workers'; Category = 'Serverless' }
    )
    'Supabase' = @(
        @{ Pattern = '\.supabase\.co$'; Type = 'Supabase'; Category = 'Backend Platform' }
    )
    'Railway' = @(
        @{ Pattern = '\.railway\.app$'; Type = 'Railway'; Category = 'Cloud Platform' }
    )
    'Render' = @(
        @{ Pattern = '\.render\.com$'; Type = 'Render'; Category = 'Cloud Platform' },
        @{ Pattern = '\.onrender\.com$'; Type = 'Render'; Category = 'Cloud Platform' }
    )
    'Fly.io' = @(
        @{ Pattern = '\.fly\.dev$'; Type = 'Fly.io'; Category = 'Cloud Platform' }
    )
}

function Write-Info {
    param([string]$Message, [string]$Color = 'White')
    Write-Host $Message -ForegroundColor $Color
}

function Write-Error {
    param([string]$Message, [string]$ErrorDetail = '')
    $fullMessage = if ($ErrorDetail) { "$Message - $ErrorDetail" } else { $Message }
    Write-Host "[ERROR] $fullMessage" -ForegroundColor Red
}

function Get-SafeGeoInfo {
    param([string]$IP, [int]$DelayMs = 500)
    
    # Skip if disabled
    if ($SkipGeo) {
        return @{ city = $null; region = $null; country = $null; org = $null }
    }
    
    # Check cache first
    if ($script:GeoCache.ContainsKey($IP)) {
        Write-Verbose "Using cached geo info for $IP"
        return $script:GeoCache[$IP]
    }
    
    try {
        # Add delay to prevent rate limiting
        Start-Sleep -Milliseconds $DelayMs
        
        $geoUrl = "https://ipinfo.io/$IP/json"
        $geoData = Invoke-RestMethod -Uri $geoUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        
        # Cache the result
        $script:GeoCache[$IP] = $geoData
        Write-Verbose "Cached geo info for $IP"
        
        return $geoData
    }
    catch {
        if ($_.Exception.Message -match "429|Too Many Requests") {
            Write-Warning "Rate limited by geo service for $IP - adding to cache as unavailable"
            # Cache the failure to avoid retrying
            $script:GeoCache[$IP] = @{ city = $null; region = $null; country = $null; org = $null; error = "Rate Limited" }
        } else {
            Write-Warning "Failed to get geo info for $IP`: $($_.Exception.Message)"
            $script:GeoCache[$IP] = @{ city = $null; region = $null; country = $null; org = $null; error = $_.Exception.Message }
        }
        return $script:GeoCache[$IP]
    }
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Get-SafeWebRequest {
    param(
        [string]$Uri,
        [string]$Method = 'GET',
        [int]$TimeoutSec = 15,
        [string]$ApiSubscriptionKey
    )
    
    $headers = @{
        'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
        'Accept' = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        'Accept-Language' = 'en-US,en;q=0.5'
        'Accept-Encoding' = 'gzip, deflate, br'
        'Upgrade-Insecure-Requests' = '1'
    }
    
    # Add subscription key header if provided
    if ($ApiSubscriptionKey) {
        $headers['ocp-apim-subscription-key'] = $ApiSubscriptionKey
        Write-Host "[INFO] Using API subscription key for request" -ForegroundColor Cyan
    }
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -Headers $headers -Method $Method -TimeoutSec $TimeoutSec -ErrorAction Stop
        $stopwatch.Stop()
        
        # Add custom properties for performance metrics
        $response | Add-Member -NotePropertyName 'ElapsedMilliseconds' -NotePropertyValue $stopwatch.ElapsedMilliseconds
        
        return $response
    }
    catch {
        $stopwatch.Stop()
        $statusCode = 0
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        
        # For HEAD requests, try to fall back to GET if we get certain error codes
        if ($Method -eq 'HEAD' -and $statusCode -in @(404, 405, 501, 502, 503)) {
            try {
                Write-Warning "HEAD request failed for $Uri (Status: $statusCode), trying GET request"
                $stopwatch.Restart()
                $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -Headers $headers -Method 'GET' -TimeoutSec 5 -ErrorAction Stop
                $stopwatch.Stop()
                $response | Add-Member -NotePropertyName 'ElapsedMilliseconds' -NotePropertyValue $stopwatch.ElapsedMilliseconds
                return $response
            }
            catch {
                # If GET also fails, just log and return null
                Write-Warning "Both HEAD and GET requests failed for $Uri`: $($_.Exception.Message)"
                return $null
            }
        }
        # Try with shorter timeout for HEAD requests
        elseif ($Method -eq 'HEAD' -and $TimeoutSec -gt 5) {
            try {
                $stopwatch.Restart()
                $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -Headers $headers -Method $Method -TimeoutSec 5 -ErrorAction Stop
                $stopwatch.Stop()
                $response | Add-Member -NotePropertyName 'ElapsedMilliseconds' -NotePropertyValue $stopwatch.ElapsedMilliseconds
                return $response
            }
            catch {
                Write-Warning "Failed $Method request to $Uri`: $($_.Exception.Message)"
                return $null
            }
        } else {
            Write-Warning "Failed $Method request to $Uri`: $($_.Exception.Message)"
            # Try to extract response from failed request if available (4xx/5xx responses)
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                Write-Host "[DEBUG] Response status: $statusCode" -ForegroundColor Yellow
                
                # For 4xx/5xx responses, try to make a second request that captures the response
                try {
                    # Use .NET HttpClient to get the full response including headers for error responses
                    $httpClient = [System.Net.Http.HttpClient]::new()
                    $httpClient.Timeout = [TimeSpan]::FromSeconds(10)
                    
                    # Add headers
                    $httpClient.DefaultRequestHeaders.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                    if ($ApiSubscriptionKey) {
                        $httpClient.DefaultRequestHeaders.Add('ocp-apim-subscription-key', $ApiSubscriptionKey)
                    }
                    
                    $stopwatch.Restart()
                    $httpResponse = $httpClient.GetAsync($Uri).Result
                    $stopwatch.Stop()
                    
                    # Create a compatible response object
                    $responseHeaders = @{}
                    foreach ($header in $httpResponse.Headers) {
                        $responseHeaders[$header.Key] = $header.Value -join ', '
                    }
                    foreach ($header in $httpResponse.Content.Headers) {
                        $responseHeaders[$header.Key] = $header.Value -join ', '
                    }
                    
                    $result = [PSCustomObject]@{
                        StatusCode = [int]$httpResponse.StatusCode
                        Headers = $responseHeaders
                        ElapsedMilliseconds = $stopwatch.ElapsedMilliseconds
                        IsErrorResponse = $true
                    }
                    
                    $httpClient.Dispose()
                    
                    Write-Host "[INFO] Captured $($responseHeaders.Count) headers from error response" -ForegroundColor Cyan
                    return $result
                }
                catch {
                    Write-Warning "Could not extract error response headers: $($_.Exception.Message)"
                }
            }
            return $null
        }
    }
}

function Get-OriginType {
    param(
        [string]$Domain,
        [string[]]$CNAMEChain,
        [string]$IPOwner,
        $Headers
    )
    
    $detectedOrigins = @()
    
    # Collect all sources to search
    $searchSources = @($Domain)
    if ($CNAMEChain) {
        $searchSources += $CNAMEChain
    }
    if ($IPOwner) {
        $searchSources += $IPOwner
    }
    
    # Add server headers if available
    if ($Headers -and $Headers['Server']) {
        $searchSources += $Headers['Server']
    }
    
    # Search through origin patterns
    foreach ($originGroup in $script:OriginPatterns.Keys) {
        foreach ($patternInfo in $script:OriginPatterns[$originGroup]) {
            $pattern = $patternInfo.Pattern
            
            foreach ($source in $searchSources) {
                if ($source -and $source -match $pattern) {
                    $detectedOrigins += [PSCustomObject]@{
                        Provider = $originGroup
                        Type = $patternInfo.Type
                        Category = $patternInfo.Category
                        MatchedOn = $source
                        MatchedPattern = $pattern
                    }
                    break # Only match once per pattern
                }
            }
        }
    }
    
    # If no specific origin detected, try to categorize based on IP owner or hosting patterns
    if ($detectedOrigins.Count -eq 0 -and $IPOwner) {
        $ipOwnerLower = $IPOwner.ToLower()
        
        # Skip if this is a known CDN or DDoS protection provider (not an origin)
        $isKnownCDNorDDoS = $false
        
        # Check against CDN patterns
        foreach ($cdnName in $script:CDNPatterns.Keys) {
            foreach ($pattern in $script:CDNPatterns[$cdnName]) {
                if ($ipOwnerLower -like "*$($pattern.ToLower())*") {
                    $isKnownCDNorDDoS = $true
                    break
                }
            }
            if ($isKnownCDNorDDoS) { break }
        }
        
        # Check against DDoS patterns if not already identified
        if (-not $isKnownCDNorDDoS) {
            foreach ($ddosName in $script:DDoSPatterns.Keys) {
                foreach ($pattern in $script:DDoSPatterns[$ddosName]) {
                    if ($ipOwnerLower -like "*$($pattern.ToLower())*") {
                        $isKnownCDNorDDoS = $true
                        break
                    }
                }
                if ($isKnownCDNorDDoS) { break }
            }
        }
        
        # Only categorize as origin if it's not a known CDN/DDoS provider
        if (-not $isKnownCDNorDDoS) {
        # Common hosting providers and cloud platforms
        $hostingPatterns = @{
            'amazon' = @{ Type = 'Amazon Web Services'; Category = 'Cloud Platform' }
            'aws' = @{ Type = 'Amazon Web Services'; Category = 'Cloud Platform' }
            'microsoft' = @{ Type = 'Microsoft Azure'; Category = 'Cloud Platform' }
            'azure' = @{ Type = 'Microsoft Azure'; Category = 'Cloud Platform' }
            'google' = @{ Type = 'Google Cloud Platform'; Category = 'Cloud Platform' }
            'digitalocean' = @{ Type = 'DigitalOcean'; Category = 'Cloud Platform' }
            'godaddy' = @{ Type = 'GoDaddy Hosting'; Category = 'Web Hosting' }
            'bluehost' = @{ Type = 'Bluehost'; Category = 'Web Hosting' }
            'hostgator' = @{ Type = 'HostGator'; Category = 'Web Hosting' }
            'siteground' = @{ Type = 'SiteGround'; Category = 'Web Hosting' }
            'dreamhost' = @{ Type = 'DreamHost'; Category = 'Web Hosting' }
            'linode' = @{ Type = 'Linode'; Category = 'Cloud Hosting' }
            'vultr' = @{ Type = 'Vultr'; Category = 'Cloud Hosting' }
            'ovh' = @{ Type = 'OVH'; Category = 'Cloud Hosting' }
            'hetzner' = @{ Type = 'Hetzner'; Category = 'Cloud Hosting' }
            'heroku' = @{ Type = 'Heroku'; Category = 'Cloud Platform' }
            'vercel' = @{ Type = 'Vercel'; Category = 'Static Hosting' }
            'netlify' = @{ Type = 'Netlify'; Category = 'Static Hosting' }
            'railway' = @{ Type = 'Railway'; Category = 'Cloud Platform' }
            'render' = @{ Type = 'Render'; Category = 'Cloud Platform' }
            'fly.io' = @{ Type = 'Fly.io'; Category = 'Cloud Platform' }
        }
        
        foreach ($provider in $hostingPatterns.Keys) {
                if ($ipOwnerLower -like "*$provider*") {
                    $detectedOrigins += [PSCustomObject]@{
                        Provider = $provider.ToUpper()
                        Type = $hostingPatterns[$provider].Type
                        Category = $hostingPatterns[$provider].Category
                        MatchedOn = $IPOwner
                        MatchedPattern = "IP Owner contains '$provider'"
                    }
                    break
                }
            }
        }
    }
    
    # If still no origin detected, analyze server headers for web server technology
    if ($detectedOrigins.Count -eq 0 -and $Headers) {
        $serverHeader = $null
        $poweredByHeader = $null
        
        # Get server and technology headers
        if ($Headers['Server']) {
            $serverHeader = $Headers['Server'].ToLower()
        }
        if ($Headers['X-Powered-By']) {
            $poweredByHeader = $Headers['X-Powered-By'].ToLower()
        }
        
        # Analyze server technology
        if ($serverHeader) {
            if ($serverHeader -like '*apache*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Apache Web Server'
                    Type = 'Apache HTTP Server'
                    Category = 'Web Server Technology'
                    MatchedOn = $Headers['Server']
                    MatchedPattern = 'Server header contains Apache'
                }
            }
            elseif ($serverHeader -like '*nginx*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Nginx Web Server'
                    Type = 'Nginx HTTP Server'
                    Category = 'Web Server Technology'
                    MatchedOn = $Headers['Server']
                    MatchedPattern = 'Server header contains Nginx'
                }
            }
            elseif ($serverHeader -like '*iis*' -or $serverHeader -like '*microsoft*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Microsoft IIS'
                    Type = 'Internet Information Services'
                    Category = 'Web Server Technology'
                    MatchedOn = $Headers['Server']
                    MatchedPattern = 'Server header contains IIS/Microsoft'
                }
            }
            elseif ($serverHeader -like '*litespeed*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'LiteSpeed'
                    Type = 'LiteSpeed Web Server'
                    Category = 'Web Server Technology'
                    MatchedOn = $Headers['Server']
                    MatchedPattern = 'Server header contains LiteSpeed'
                }
            }
            elseif ($serverHeader -like '*vercel*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Vercel'
                    Type = 'Vercel Edge Network'
                    Category = 'Static Hosting'
                    MatchedOn = $Headers['Server']
                    MatchedPattern = 'Server header contains Vercel'
                }
            }
            elseif ($serverHeader -like '*envoy*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Envoy Proxy'
                    Type = 'Envoy Service Mesh/Load Balancer'
                    Category = 'Proxy/Load Balancer'
                    MatchedOn = $Headers['Server']
                    MatchedPattern = 'Server header contains Envoy'
                }
            }
            elseif ($serverHeader -like '*istio*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Istio Service Mesh'
                    Type = 'Istio Service Mesh'
                    Category = 'Service Mesh'
                    MatchedOn = $Headers['Server']
                    MatchedPattern = 'Server header contains Istio'
                }
            }
            elseif ($serverHeader -like '*traefik*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Traefik'
                    Type = 'Traefik Reverse Proxy'
                    Category = 'Proxy/Load Balancer'
                    MatchedOn = $Headers['Server']
                    MatchedPattern = 'Server header contains Traefik'
                }
            }
            elseif ($serverHeader -like '*haproxy*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'HAProxy'
                    Type = 'HAProxy Load Balancer'
                    Category = 'Proxy/Load Balancer'
                    MatchedOn = $Headers['Server']
                    MatchedPattern = 'Server header contains HAProxy'
                }
            }
            elseif ($serverHeader -like '*kong*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Kong Gateway'
                    Type = 'Kong API Gateway'
                    Category = 'API Gateway'
                    MatchedOn = $Headers['Server']
                    MatchedPattern = 'Server header contains Kong'
                }
            }
            elseif ($serverHeader -like '*ambassador*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Ambassador'
                    Type = 'Ambassador API Gateway'
                    Category = 'API Gateway'
                    MatchedOn = $Headers['Server']
                    MatchedPattern = 'Server header contains Ambassador'
                }
            }
            elseif ($serverHeader -like '*linkerd*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Linkerd'
                    Type = 'Linkerd Service Mesh'
                    Category = 'Service Mesh'
                    MatchedOn = $Headers['Server']
                    MatchedPattern = 'Server header contains Linkerd'
                }
            }
        }
        
        # Check for platform-specific headers
        if ($Headers) {
            # Vercel-specific headers
            if ($Headers['x-vercel-cache'] -or $Headers['x-vercel-id'] -or $Headers['x-matched-path']) {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Vercel'
                    Type = 'Vercel Edge Network'
                    Category = 'Static Hosting'
                    MatchedOn = 'Vercel-specific headers detected'
                    MatchedPattern = 'x-vercel-* headers present'
                }
            }
            # Netlify-specific headers
            elseif ($Headers['x-nf-request-id'] -or $Headers['server'] -like '*netlify*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Netlify'
                    Type = 'Netlify Edge Network'
                    Category = 'Static Hosting'
                    MatchedOn = 'Netlify-specific headers detected'
                    MatchedPattern = 'x-nf-* or netlify server headers present'
                }
            }
            # Envoy Proxy headers (common in service meshes)
            elseif ($Headers['x-envoy-upstream-service-time'] -or $Headers['x-envoy-decorator-operation'] -or $Headers['x-envoy-expected-rq-timeout-ms']) {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Envoy Proxy'
                    Type = 'Envoy Service Mesh/Load Balancer'
                    Category = 'Proxy/Load Balancer'
                    MatchedOn = 'Envoy-specific headers detected'
                    MatchedPattern = 'x-envoy-* headers present'
                }
            }
            # Istio service mesh headers
            elseif ($Headers['x-istio-version'] -or $Headers['x-b3-traceid'] -or $Headers['x-b3-spanid']) {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Istio Service Mesh'
                    Type = 'Istio Service Mesh'
                    Category = 'Service Mesh'
                    MatchedOn = 'Istio/B3 tracing headers detected'
                    MatchedPattern = 'x-istio-* or x-b3-* headers present'
                }
            }
            # Kong API Gateway headers
            elseif ($Headers['x-kong-upstream-latency'] -or $Headers['x-kong-proxy-latency'] -or $Headers['x-kong-request-id']) {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Kong Gateway'
                    Type = 'Kong API Gateway'
                    Category = 'API Gateway'
                    MatchedOn = 'Kong-specific headers detected'
                    MatchedPattern = 'x-kong-* headers present'
                }
            }
            # Linkerd service mesh headers
            elseif ($Headers['l5d-dst-canonical'] -or $Headers['l5d-dst-residual'] -or $Headers['l5d-reqid']) {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'Linkerd'
                    Type = 'Linkerd Service Mesh'
                    Category = 'Service Mesh'
                    MatchedOn = 'Linkerd-specific headers detected'
                    MatchedPattern = 'l5d-* headers present'
                }
            }
        }
        
        # Analyze X-Powered-By header
        if ($poweredByHeader -and $detectedOrigins.Count -eq 0) {
            if ($poweredByHeader -like '*php*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'PHP'
                    Type = 'PHP Application Server'
                    Category = 'Application Technology'
                    MatchedOn = $Headers['X-Powered-By']
                    MatchedPattern = 'X-Powered-By header contains PHP'
                }
            }
            elseif ($poweredByHeader -like '*asp.net*') {
                $detectedOrigins += [PSCustomObject]@{
                    Provider = 'ASP.NET'
                    Type = 'ASP.NET Application Server'
                    Category = 'Application Technology'
                    MatchedOn = $Headers['X-Powered-By']
                    MatchedPattern = 'X-Powered-By header contains ASP.NET'
                }
            }
        }
    }
    
    return $detectedOrigins | Select-Object -Unique Provider, Type, Category, MatchedOn
}

function Get-DomainInfo {
    param([string]$Domain)
    
    $result = [PSCustomObject]@{
        Domain = $Domain
        IP = $null
        CNAMEChain = @()
        CNAMEDetails = @()
        IPOwner = 'Unknown'
        Geo = 'Unknown'
        DNSResolver = $null
        DNSResolverGeo = 'Unknown'
        DNSResolverOwner = 'Unknown'
        SOARecord = $null
    }
    
    # Get IP address with timeout
    try {
        $task = [System.Net.Dns]::GetHostAddressesAsync($Domain)
        if ($task.Wait(3000)) {  # 3 second timeout
            $addresses = $task.Result
            if ($addresses -and $addresses.Count -gt 0) {
                $result.IP = $addresses[0].IPAddressToString
            }
        } else {
            Write-Warning "DNS resolution timed out for $Domain"
        }
    }
    catch {
        Write-Warning "Failed to resolve IP for $Domain`: $($_.Exception.Message)"
    }
    
    # Get detailed CNAME chain with TTL (with shorter timeout)
    try {
        $chain = @()
        $chainDetails = @()
        $current = $Domain
        for ($i = 0; $i -lt 10; $i++) {  # Increased back to 10 for full chain
            $dnsResult = Resolve-DnsName -Name $current -Type CNAME -ErrorAction SilentlyContinue -DnsOnly
            if ($dnsResult -and $dnsResult.Count -gt 0) {
                # Handle multiple results - take the first one
                $cnameRecord = $dnsResult | Where-Object { $_.Type -eq 'CNAME' } | Select-Object -First 1
                if ($cnameRecord -and $cnameRecord.NameHost) {
                    $chain += $cnameRecord.NameHost
                    $chainDetails += [PSCustomObject]@{
                        Name = $cnameRecord.Name
                        Type = $cnameRecord.Type
                        TTL = $cnameRecord.TTL
                        NameHost = $cnameRecord.NameHost
                        Section = $cnameRecord.Section
                    }
                    $current = $cnameRecord.NameHost
                } else {
                    break
                }
            } else {
                # Try to get A record for the final name to complete the chain
                $aResult = Resolve-DnsName -Name $current -Type A -ErrorAction SilentlyContinue -DnsOnly
                if ($aResult -and $aResult.Count -gt 0) {
                    $aRecord = $aResult | Where-Object { $_.Type -eq 'A' } | Select-Object -First 1
                    if ($aRecord) {
                        $chainDetails += [PSCustomObject]@{
                            Name = $aRecord.Name
                            Type = $aRecord.Type
                            TTL = $aRecord.TTL
                            NameHost = $aRecord.IPAddress
                            Section = $aRecord.Section
                        }
                    }
                }
                break
            }
        }
        $result.CNAMEChain = $chain
        $result.CNAMEDetails = $chainDetails
    }
    catch {
        Write-Warning "Failed to get CNAME chain for $Domain`: $($_.Exception.Message)"
    }
    
    # Get SOA record
    try {
        $finalDomain = if ($result.CNAMEChain.Count -gt 0) { 
            # Extract base domain from final CNAME
            $final = $result.CNAMEChain[-1]
            $parts = $final.Split('.')
            if ($parts.Count -ge 2) {
                $parts[-2] + '.' + $parts[-1]
            } else {
                $final
            }
        } else { 
            $Domain 
        }
        $soaResult = Resolve-DnsName -Name $finalDomain -Type SOA -ErrorAction SilentlyContinue
        if ($soaResult) {
            $result.SOARecord = $soaResult | Select-Object -First 1
        }
    }
    catch {
        Write-Warning "Failed to get SOA record for $Domain`: $($_.Exception.Message)"
    }
    
    # Get DNS resolver info
    try {
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 }
        if ($dnsServers) {
            $result.DNSResolver = $dnsServers[0].ServerAddresses[0]
        }
    }
    catch {
        Write-Warning "Failed to get DNS resolver info`: $($_.Exception.Message)"
    }
    
    # Get IP owner (WHOIS)
    if ($result.IP) {
        try {
            $whoisUrl = "https://rdap.arin.net/registry/ip/$($result.IP)"
            $whoisData = Invoke-RestMethod -Uri $whoisUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            
            if ($whoisData.fullName) {
                $result.IPOwner = $whoisData.fullName
            }
            elseif ($whoisData.entities) {
                foreach ($entity in $whoisData.entities) {
                    if ($entity.vcardArray -and $entity.vcardArray[1]) {
                        foreach ($vcard in $entity.vcardArray[1]) {
                            if ($vcard[0] -eq 'fn' -and $vcard[3]) {
                                $result.IPOwner = $vcard[3]
                                break
                            }
                        }
                        if ($result.IPOwner -ne 'Unknown') { break }
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to get IP owner for $($result.IP)`: $($_.Exception.Message)"
        }
        
        # Get geolocation with caching and rate limiting
        $geoData = Get-SafeGeoInfo -IP $result.IP -DelayMs 750
        if ($geoData -and -not $geoData.error) {
            if ($geoData.city -or $geoData.region -or $geoData.country) {
                $geoArray = @($geoData.city, $geoData.region, $geoData.country) | Where-Object { $_ }
                $result.Geo = $geoArray -join ', '
            }
        }
    }
    
    # Get DNS resolver geo and owner with caching and rate limiting
    if ($result.DNSResolver -and $result.DNSResolver -ne $result.IP) {
        $geoData = Get-SafeGeoInfo -IP $result.DNSResolver -DelayMs 750
        if ($geoData -and -not $geoData.error) {
            if ($geoData.city -or $geoData.region -or $geoData.country) {
                $geoArray = @($geoData.city, $geoData.country) | Where-Object { $_ }
                $result.DNSResolverGeo = $geoArray -join ', '
            }
            if ($geoData.org) {
                $result.DNSResolverOwner = $geoData.org
            }
        }
    }
    
    return $result
}

function Get-CDNEdgeLocation {
    param([string[]]$CNAMEChain, [hashtable]$Headers)
    
    $edgeLocation = 'Unknown'
    
    # Check for Akamai edge location in CNAME
    foreach ($cname in $CNAMEChain) {
        if ($cname -match '\.akamaiedge\.net$') {
            if ($cname -match '([a-z]+\d*)\..*\.akamaiedge\.net') {
                $edgeLocation = $matches[1]
                break
            }
        }
    }
    
    # Check for other CDN edge indicators in headers
    if ($Headers) {
        foreach ($header in $Headers.GetEnumerator()) {
            if ($header.Key -like '*pop*' -or $header.Key -like '*edge*' -or $header.Key -like '*location*') {
                $edgeLocation = $header.Value
                break
            }
        }
    }
    
    return $edgeLocation
}

function Get-CompressionInfo {
    param($Response)  # Accept any response type (WebResponseObject or custom PSObject)
    
    $result = [PSCustomObject]@{
        ContentEncoding = 'None'
        OriginalSize = 0
        CompressedSize = 0
        CompressionRatio = 0
    }
    
    if ($Response) {
        if ($Response.Headers['Content-Encoding']) {
            $result.ContentEncoding = $Response.Headers['Content-Encoding']
        }
        
        if ($Response.Headers['x-original-content-length']) {
            try {
                $result.OriginalSize = [int]$Response.Headers['x-original-content-length']
            } catch {}
        }
        
        if ($Response.Headers['Content-Length']) {
            try {
                $result.CompressedSize = [int]$Response.Headers['Content-Length']
            } catch {}
        } elseif ($Response.Content) {
            $result.CompressedSize = [System.Text.Encoding]::UTF8.GetByteCount($Response.Content)
        }
        
        if ($result.OriginalSize -gt 0 -and $result.CompressedSize -gt 0) {
            $result.CompressionRatio = [math]::Round((1 - ($result.CompressedSize / $result.OriginalSize)) * 100, 2)
        }
    }
    
    return $result
}

function Get-CacheStatus {
    param([hashtable]$Headers)
    
    $cacheStatus = 'Unknown'
    $cacheControl = 'Not Set'
    
    if ($Headers) {
        # Check various cache-related headers
        $cacheHeaders = @('X-Cache', 'X-Cache-Status', 'CF-Cache-Status', 'X-Served-By', 'X-Fastly-Cache')
        foreach ($header in $cacheHeaders) {
            if ($Headers[$header]) {
                $cacheStatus = $Headers[$header]
                break
            }
        }
        
        if ($Headers['Cache-Control']) {
            $cacheControl = $Headers['Cache-Control']
        }
    }
    
    return [PSCustomObject]@{
        Status = $cacheStatus
        CacheControl = $cacheControl
    }
}

function Get-RedirectChain {
    param([string]$Url)
    
    $chain = @()
    $currentUrl = $Url
    $maxRedirects = 10
    
    for ($i = 0; $i -lt $maxRedirects; $i++) {
        try {
            $response = Invoke-WebRequest -Uri $currentUrl -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue
            $chain += [PSCustomObject]@{
                StatusCode = $response.StatusCode
                Url = $currentUrl
            }
            break
        }
        catch {
            $statusCode = 0
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            
            $chain += [PSCustomObject]@{
                StatusCode = $statusCode
                Url = $currentUrl
            }
            
            if ($statusCode -in @(301, 302, 303, 307, 308)) {
                $location = $_.Exception.Response.Headers.Location
                if ($location) {
                    $currentUrl = $location.ToString()
                    continue
                }
            }
            break
        }
    }
    
    return $chain
}















function Get-CDNProviders {
    param(
        [string[]]$CNAMEChain,
        $Headers,
        [string]$IPOwner
    )
    
    $detectedCDNs = @()
    
    # Build search text from all sources
    $searchComponents = @()
    
    # Add CNAME chain
    if ($CNAMEChain) {
        $searchComponents += $CNAMEChain
    }
    
    # Add IP Owner
    if ($IPOwner) {
        $searchComponents += $IPOwner
    }
    
    # Add headers (handle different header types)
    if ($Headers) {
        if ($Headers -is [hashtable]) {
            $searchComponents += $Headers.Keys
            $searchComponents += $Headers.Values
        } elseif ($Headers.GetEnumerator) {
            foreach ($header in $Headers.GetEnumerator()) {
                $searchComponents += $header.Key
                $searchComponents += $header.Value
            }
        }
    }
    
    $searchText = ($searchComponents -join ' ').ToLower()
    
    foreach ($cdnName in $script:CDNPatterns.Keys) {
        foreach ($pattern in $script:CDNPatterns[$cdnName]) {
            if ($searchText -like "*$($pattern.ToLower())*") {
                $detectedCDNs += $cdnName
                break
            }
        }
    }
    
    return $detectedCDNs | Select-Object -Unique
}

function Get-PrimaryCDNFromHeaders {
    param(
        $Headers
    )
    
    if (-not $Headers) {
        return $null
    }
    
    # Define primary CDN detection patterns based on specific HTTP headers
    # These are headers that definitively indicate the active CDN serving the content
    # Order matters - most specific/definitive patterns first
    $primaryCDNHeaders = [ordered]@{
        'Azure Front Door' = @('x-azure-ref', 'x-msedge-ref') # Azure Front Door headers - check first
        'Cloudflare' = @('cf-ray', 'cf-cache-status', '__cf_bm', '__cfduid')
        'Fastly' = @('x-served-by.*fastly', 'x-fastly-request-id', 'x-cache.*fastly', 'fastly-restarts', 'fastly-debug')
        'Amazon CloudFront' = @('x-amz-cf-id', 'x-amz-cf-pop', 'via.*cloudfront')
        'Akamai' = @('x-akamai-.*', 'akamai-origin-hop', 'server.*akamai')
        'Netflix Open Connect' = @('x-netflix-.*', 'server.*netflix')
        'Google CDN' = @('server.*gfe', 'x-goog-.*(?!analytics)') # Exclude Google Analytics
        'StackPath' = @('x-hw-.*', 'x-stackpath-.*', 'server.*stackpath')
        'KeyCDN' = @('x-keycdn-.*', 'server.*keycdn')
        'CDN77' = @('x-cdn77-.*', 'server.*cdn77')
        'BunnyCDN' = @('x-bunnycdn-.*', 'server.*bunnycdn')
        'Vercel' = @('x-vercel-.*', 'server.*vercel')
        'Netlify' = @('x-nf-.*', 'server.*netlify')
    }
    
    # Convert headers to searchable format
    $headerText = ''
    if ($Headers -is [hashtable]) {
        foreach ($key in $Headers.Keys) {
            $headerText += "$($key.ToLower()): $($Headers[$key].ToString().ToLower()) "
        }
    } elseif ($Headers.GetEnumerator) {
        foreach ($header in $Headers.GetEnumerator()) {
            $headerText += "$($header.Key.ToLower()): $($header.Value.ToString().ToLower()) "
        }
    }
    
    # Check for primary CDN indicators (most specific first)
    # Return the FIRST match to avoid multiple CDN detection
    
    # Priority check for Azure Front Door first (before looping through all CDNs)
    if ($Headers -is [hashtable]) {
        foreach ($key in $Headers.Keys) {
            if ($key -ieq 'x-azure-ref' -or $key -ieq 'x-msedge-ref') {
                Write-Verbose "Primary CDN detected: Azure Front Door (matched header: $key)"
                return 'Azure Front Door'
            }
        }
    } elseif ($Headers.GetEnumerator) {
        foreach ($header in $Headers.GetEnumerator()) {
            if ($header.Key -ieq 'x-azure-ref' -or $header.Key -ieq 'x-msedge-ref') {
                Write-Verbose "Primary CDN detected: Azure Front Door (matched header: $($header.Key))"
                return 'Azure Front Door'
            }
        }
    }
    
    # If no Azure Front Door headers found, check other CDNs
    foreach ($cdnName in $primaryCDNHeaders.Keys) {
        # Skip Azure Front Door since we already checked it above
        if ($cdnName -eq 'Azure Front Door') { continue }
        
        foreach ($pattern in $primaryCDNHeaders[$cdnName]) {
            if ($headerText -match $pattern) {
                Write-Verbose "Primary CDN detected: $cdnName (matched pattern: $pattern)"
                return $cdnName
            }
        }
    }
    
    return $null
}

function Get-PrimaryCDNFromDNS {
    param(
        [string[]]$CNAMEChain,
        [string]$IPOwner,
        $SOARecord
    )
    
    # Define DNS-based CDN detection patterns - more specific patterns
    $dnsCDNPatterns = @{
        'Cloudflare' = @('cloudflare.com', 'cloudflare.net', 'cf-ray')
        'Akamai' = @('akamai.net', 'akamaiedge.net', 'edgesuite.net', 'edgekey.net', 'akamaitechnologies')
        'Fastly' = @('fastly.com', 'fastly.net')
        'Amazon CloudFront' = @('cloudfront.net', 'amazonaws.com')
        'Azure Front Door' = @('azurefd.net')
        'Azure CDN' = @('azureedge.net')
        'Google CDN' = @('googleapis.com', 'googlehosted.com', '1e100.net')
        'StackPath' = @('stackpath.com', 'highwinds.com', 'hwcdn.net')
        'KeyCDN' = @('keycdn.com')
        'CDN77' = @('cdn77.org')
        'BunnyCDN' = @('b-cdn.net', 'bunnycdn.com')
    }
    
    # Collect all DNS sources to search
    $searchSources = @()
    
    # Add CNAME chain - prioritize the most specific (first) entries
    if ($CNAMEChain) {
        $searchSources += $CNAMEChain
    }
    
    # Add IP Owner with lower priority
    if ($IPOwner) {
        $searchSources += $IPOwner
    }
    
    # Add SOA record information
    if ($SOARecord) {
        if ($SOARecord.Name) { $searchSources += $SOARecord.Name }
        if ($SOARecord.NameAdministrator) { $searchSources += $SOARecord.NameAdministrator }
    }
    
    $searchText = ($searchSources -join ' ').ToLower()
    
    # Check for primary CDN indicators in DNS data
    # Return the FIRST match to avoid multiple CDN detection
    foreach ($cdnName in $dnsCDNPatterns.Keys) {
        foreach ($pattern in $dnsCDNPatterns[$cdnName]) {
            if ($searchText -like "*$($pattern.ToLower())*") {
                Write-Verbose "Primary CDN detected via DNS: $cdnName (matched pattern: $pattern)"
                return $cdnName
            }
        }
    }
    
    return $null
}

function Get-CDNsFromURLs {
    param(
        [string]$Content,
        [string]$BaseDomain
    )
    
    $detectedCDNs = @()
    
    if (-not $Content) {
        return $detectedCDNs
    }
    
    # Extract URLs from various HTML attributes and CSS
    $urlPatterns = @(
        # src attributes (images, scripts, iframes, etc.)
        'src=["'']([^"'']+)["'']',
        # href attributes (stylesheets, links)
        'href=["'']([^"'']+)["'']',
        # CSS url() references
        'url\(["'']?([^"''\)]+)["'']?\)',
        # srcset attributes for responsive images
        'srcset=["'']([^"'']+)["'']',
        # data-src attributes (lazy loading)
        'data-src=["'']([^"'']+)["'']'
    )
    
    $extractedUrls = @()
    
    foreach ($pattern in $urlPatterns) {
        $matches = [regex]::Matches($Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($match in $matches) {
            $url = $match.Groups[1].Value
            # Only include external URLs (not relative paths or data URIs or same domain)
            if ($url -match '^https?://' -and $url -notmatch "^https?://([^/]*\.)?$([regex]::Escape($BaseDomain))") {
                $extractedUrls += $url
            }
        }
    }
    
    # For srcset, we need to handle multiple URLs separated by commas
    $srcsetMatches = [regex]::Matches($Content, 'srcset=["'']([^"'']+)["'']', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($match in $srcsetMatches) {
        $srcsetValue = $match.Groups[1].Value
        # Split by comma and extract URLs (ignoring the width/density descriptors)
        $srcsetUrls = $srcsetValue -split ',' | ForEach-Object {
            $_.Trim() -replace '\s+\d+[wx]?\s*$', ''  # Remove width/density descriptors
        }
        foreach ($url in $srcsetUrls) {
            if ($url -match '^https?://' -and $url -notmatch "^https?://([^/]*\.)?$([regex]::Escape($BaseDomain))") {
                $extractedUrls += $url
            }
        }
    }
    
    # Remove duplicates and analyze each URL for CDN patterns
    $uniqueUrls = $extractedUrls | Select-Object -Unique
    
    Write-Verbose "Found $($uniqueUrls.Count) unique external URLs to analyze for CDNs"
    
    foreach ($url in $uniqueUrls) {
        try {
            $uri = [System.Uri]$url
            $domain = $uri.Host.ToLower()
            
            # Check each CDN pattern against the domain
            foreach ($cdnName in $script:CDNPatterns.Keys) {
                foreach ($pattern in $script:CDNPatterns[$cdnName]) {
                    if ($domain -like "*$($pattern.ToLower())*") {
                        $detectedCDNs += [PSCustomObject]@{
                            CDN = $cdnName
                            Domain = $domain
                            URL = $url
                            Pattern = $pattern
                        }
                        break  # Only match once per URL per CDN
                    }
                }
            }
        }
        catch {
            # Skip invalid URLs
            Write-Verbose "Skipping invalid URL: $url"
        }
    }
    
    return $detectedCDNs
}

function Get-DDoSProviders {
    param(
        [string[]]$CNAMEChain,
        $Headers,
        [string]$IPOwner,
        [string[]]$DetectedCDNs = @()
    )
    
    $detectedDDoS = @()
    
    # Build search text from all sources
    $searchComponents = @()
    
    # Add CNAME chain
    if ($CNAMEChain) {
        $searchComponents += $CNAMEChain
    }
    
    # Add IP Owner
    if ($IPOwner) {
        $searchComponents += $IPOwner
    }
    
    # Add headers (handle different header types)
    if ($Headers) {
        if ($Headers -is [hashtable]) {
            $searchComponents += $Headers.Keys
            $searchComponents += $Headers.Values
        } elseif ($Headers.GetEnumerator) {
            foreach ($header in $Headers.GetEnumerator()) {
                $searchComponents += $header.Key
                $searchComponents += $header.Value
            }
        }
    }
    
    $searchText = ($searchComponents -join ' ').ToLower()
    
    # Standard pattern matching
    foreach ($ddosName in $script:DDoSPatterns.Keys) {
        foreach ($pattern in $script:DDoSPatterns[$ddosName]) {
            if ($searchText -like "*$($pattern.ToLower())*") {
                $detectedDDoS += $ddosName
                break
            }
        }
    }
    
    # Additional intelligent detection for major platforms
    # AWS Shield is enabled by default on CloudFront and other AWS services
    if ($searchText -like '*cloudfront*' -or $searchText -like '*amazonaws*' -or $searchText -like '*x-amz-cf-id*') {
        if ($detectedDDoS -notcontains 'AWS Shield') {
            $detectedDDoS += 'AWS Shield'
        }
    }
    
    # Azure Front Door includes DDoS protection - only detect if Azure Front Door is actually detected as CDN
    if ($DetectedCDNs -contains 'Azure Front Door') {
        if ($detectedDDoS -notcontains 'Azure DDoS Protection') {
            $detectedDDoS += 'Azure DDoS Protection'
        }
    }
    
    # Cloudflare provides DDoS protection with their CDN
    if ($searchText -like '*cloudflare*' -or $searchText -like '*cf-ray*') {
        if ($detectedDDoS -notcontains 'Cloudflare') {
            $detectedDDoS += 'Cloudflare'
        }
    }
    
    # Fastly includes DDoS protection
    if ($searchText -like '*fastly*' -or $searchText -like '*x-served-by*') {
        if ($detectedDDoS -notcontains 'Fastly') {
            $detectedDDoS += 'Fastly'
        }
    }
    
    # Akamai CDN includes DDoS protection capabilities
    if ($searchText -like '*akamai*' -or $searchText -like '*edgekey.net*' -or $searchText -like '*edgesuite.net*') {
        if ($detectedDDoS -notcontains 'Akamai Prolexic') {
            # Don't add "Prolexic" unless specifically detected, but note Akamai has DDoS protection
            $detectedDDoS += 'Akamai DDoS Protection'
        }
    }
    
    return $detectedDDoS | Select-Object -Unique
}

function Get-AzureFrontDoorPOP {
    param([string]$AzureRef)
    
    if ($AzureRef -match 'C1([A-Z]{2,3})') {
        $code = $matches[1]
        if ($script:AfdPopMap.ContainsKey($code)) {
            return "$code ($($script:AfdPopMap[$code]))"
        } else {
            return $code
        }
    }
    return $null
}

function Get-TLSCertificateInfo {
    param([string]$Url)
    
    if ($Url -notmatch '^https://') {
        return $null
    }
    
    try {
        $uri = [Uri]$Url
        $tcpClient = New-Object Net.Sockets.TcpClient($uri.Host, 443)
        
        try {
            $sslStream = New-Object Net.Security.SslStream($tcpClient.GetStream(), $false, {$true})
            $sslStream.AuthenticateAsClient($uri.Host)
            
            $cert = $sslStream.RemoteCertificate
            $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cert
            
            $daysLeft = ($cert2.NotAfter - (Get-Date)).Days
            
            return [PSCustomObject]@{
                Issuer = $cert2.Issuer
                Subject = $cert2.Subject
                NotAfter = $cert2.NotAfter
                DaysLeft = $daysLeft
            }
        }
        finally {
            if ($tcpClient) { $tcpClient.Close() }
        }
    }
    catch {
        Write-Warning "Failed to get TLS info for $Url`: $($_.Exception.Message)"
        return $null
    }
}

function Get-ResourceUrls {
    param([string]$HtmlContent, [string]$BaseUrl)
    
    if (-not $HtmlContent) {
        return @()
    }
    
    $urls = @()
    $patterns = @(
        'src\s*=\s*"([^"]+)"',
        "src\s*=\s*'([^']+)'",
        'href\s*=\s*"([^"]+)"',
        "href\s*=\s*'([^']+)'"
    )
    
    foreach ($pattern in $patterns) {
        $regexMatches = [regex]::Matches($HtmlContent, $pattern, 'IgnoreCase')
        foreach ($match in $regexMatches) {
            $url = $match.Groups[1].Value
            
            # Skip invalid URLs
            if (-not $url -or $url -match '^(#|javascript:|mailto:|data:|about:blank)') {
                continue
            }
            
            # Skip incomplete URLs like "https://" or "http://"
            if ($url -match '^https?://$' -or $url.Length -lt 10) {
                continue
            }
            
            # Convert relative URLs to absolute
            if ($url -notmatch '^https?://') {
                try {
                    $baseUri = New-Object System.Uri($BaseUrl)
                    $absoluteUri = New-Object System.Uri($baseUri, $url)
                    $url = $absoluteUri.AbsoluteUri
                }
                catch {
                    continue
                }
            } else {
                # Validate absolute URLs can be parsed as URI
                try {
                    $testUri = New-Object System.Uri($url)
                    # Additional check for valid hostname
                    if (-not $testUri.Host -or $testUri.Host.Length -lt 3) {
                        continue
                    }
                }
                catch {
                    continue
                }
            }
            
            $urls += $url
        }
    }
    
    return $urls | Select-Object -Unique
}

function Analyze-SingleUrl {
    param([string]$Url, [bool]$IsMainUrl = $false)
    
    $uri = [Uri]$Url
    $domain = $uri.Host
    
    if ($IsMainUrl) {
        Write-Info "Analyzing main URL: $Url" -Color Cyan
    }
    
    # Get domain information
    Write-Verbose "Getting domain info for: $domain"
    $domainInfo = Get-DomainInfo -Domain $domain
    Write-Verbose "Domain info completed"
    
    # Get redirect chain
    Write-Verbose "Getting redirect chain"
    $redirectChain = @()
    if ($IsMainUrl) {
        $redirectChain = Get-RedirectChain -Url $Url
    }
    Write-Verbose "Redirect chain completed"
    
    # Get web response
    Write-Verbose "Making web request"
    $response = Get-SafeWebRequest -Uri $Url -Method $(if ($IsMainUrl) {'GET'} else {'HEAD'}) -ApiSubscriptionKey $script:SubscriptionKey
    Write-Verbose "Web request completed"
    
    # Get TLS info for HTTPS URLs
    Write-Verbose "Getting TLS info"
    $tlsInfo = Get-TLSCertificateInfo -Url $Url
    Write-Verbose "TLS info completed"
    
    # Get cache status
    $cacheStatus = $null
    if ($response) {
        $cacheStatus = Get-CacheStatus -Headers $response.Headers
    }
    
    # Get compression info
    $compressionInfo = $null
    if ($response) {
        $compressionInfo = Get-CompressionInfo -Response $response
    }
    
    # Get CDN edge location
    $edgeLocation = 'Unknown'
    if ($response) {
        $edgeLocation = Get-CDNEdgeLocation -CNAMEChain $domainInfo.CNAMEChain -Headers $response.Headers
    }
    
    # Detect CDN providers - always try even if no response
    $allCdnProviders = @()
    $primaryCDN = $null
    $otherCDNs = @()
    
    if ($response) {
        $allCdnProviders = Get-CDNProviders -CNAMEChain $domainInfo.CNAMEChain -Headers $response.Headers -IPOwner $domainInfo.IPOwner
        $primaryCDN = Get-PrimaryCDNFromHeaders -Headers $response.Headers
    } else {
        # Even if HTTP fails, try to detect CDN from DNS/CNAME data alone
        $allCdnProviders = Get-CDNProviders -CNAMEChain $domainInfo.CNAMEChain -Headers @{} -IPOwner $domainInfo.IPOwner
    }
    
    # If no primary CDN detected from headers, try DNS-based detection
    if (-not $primaryCDN) {
        $primaryCDN = Get-PrimaryCDNFromDNS -CNAMEChain $domainInfo.CNAMEChain -IPOwner $domainInfo.IPOwner -SOARecord $domainInfo.SOARecord
    }
    
    # Separate primary CDN from others
    if ($primaryCDN -and $allCdnProviders -contains $primaryCDN) {
        $otherCDNs = $allCdnProviders | Where-Object { $_ -ne $primaryCDN }
    } else {
        # If no primary CDN detected from headers or DNS, treat first detected as primary
        if ($allCdnProviders.Count -gt 0) {
            if (-not $primaryCDN) {
                $primaryCDN = $allCdnProviders[0]
                $otherCDNs = $allCdnProviders | Select-Object -Skip 1
            } else {
                # Primary CDN was detected from DNS but not in allCdnProviders list
                $otherCDNs = $allCdnProviders
            }
        } else {
            $otherCDNs = $allCdnProviders
        }
    }
    
    # Detect DDoS protection providers
    $ddosProviders = @()
    if ($response) {
        $ddosProviders = Get-DDoSProviders -CNAMEChain $domainInfo.CNAMEChain -Headers $response.Headers -IPOwner $domainInfo.IPOwner -DetectedCDNs $allCdnProviders
    } else {
        # Even if HTTP fails, try to detect DDoS protection from DNS/CNAME data alone
        $ddosProviders = Get-DDoSProviders -CNAMEChain $domainInfo.CNAMEChain -Headers @{} -IPOwner $domainInfo.IPOwner -DetectedCDNs $allCdnProviders
    }
    
    # Detect origin type
    $originInfo = Get-OriginType -Domain $domainInfo.Domain -CNAMEChain $domainInfo.CNAMEChain -IPOwner $domainInfo.IPOwner -Headers $(if ($response) { $response.Headers } else { @{} })
    
    # Check for Azure Front Door POP
    $afdPop = $null
    if ($response -and $response.Headers['x-azure-ref']) {
        $afdPop = Get-AzureFrontDoorPOP -AzureRef $response.Headers['x-azure-ref']
    }
    
    return [PSCustomObject]@{
        Url = $Url
        Domain = $domainInfo.Domain
        IP = $domainInfo.IP
        CNAMEChain = $domainInfo.CNAMEChain
        CNAMEDetails = $domainInfo.CNAMEDetails
        IPOwner = $domainInfo.IPOwner
        Geo = $domainInfo.Geo
        DNSResolver = $domainInfo.DNSResolver
        DNSResolverGeo = $domainInfo.DNSResolverGeo
        DNSResolverOwner = $domainInfo.DNSResolverOwner
        SOARecord = $domainInfo.SOARecord
        PrimaryCDN = $primaryCDN
        OtherCDNs = $otherCDNs
        AllCDNProviders = $allCdnProviders
        DDoSProviders = $ddosProviders
        OriginInfo = $originInfo
        EdgeLocation = $edgeLocation
        Response = $response
        TLSInfo = $tlsInfo
        CacheStatus = $cacheStatus
        CompressionInfo = $compressionInfo
        AzureFrontDoorPOP = $afdPop
        RedirectChain = $redirectChain
    }
}

function Show-UrlAnalysis {
    param([PSCustomObject]$Analysis)
    
    Write-Info "`n=== URL Analysis: $($Analysis.Url) ===" -Color Yellow
    
    # Basic info
    Write-Info "Domain: $($Analysis.Domain)"
    Write-Info "IP: $($Analysis.IP)"
    Write-Info "Geo: $($Analysis.Geo)"
    Write-Info "IP Owner: $($Analysis.IPOwner)"
    
    # DNS Info - Commented out as it typically shows local router info which isn't useful
    # Write-Info "`n--- DNS Information ---" -Color Cyan
    # Write-Info "DNS Resolver IP: $($Analysis.DNSResolver)"
    # Write-Info "DNS Resolver Geo: $($Analysis.DNSResolverGeo)"
    # Write-Info "DNS Resolver Owner: $($Analysis.DNSResolverOwner)"
    
    # CNAME Chain
    if ($Analysis.CNAMEChain -and $Analysis.CNAMEChain.Count -gt 0) {
        Write-Info "`nDNS Resolution Chain:" -Color Cyan
        foreach ($detail in $Analysis.CNAMEDetails) {
            Write-Info "$($detail.Name)`t$($detail.TTL)`tIN`t$($detail.Type)`t$($detail.NameHost)"
        }
    }
    
    # SOA Record
    if ($Analysis.SOARecord) {
        Write-Info "`nSOA Record for $($Analysis.Domain):" -Color Cyan
        Write-Info "Name: $($Analysis.SOARecord.Name)"
        if ($Analysis.SOARecord.NameAdministrator) {
            Write-Info "NameAdministrator: $($Analysis.SOARecord.NameAdministrator)"
        }
        if ($Analysis.SOARecord.SerialNumber) {
            Write-Info "SerialNumber: $($Analysis.SOARecord.SerialNumber)"
        }
        if ($Analysis.SOARecord.TimeToZoneRefresh) {
            Write-Info "TimeToZoneRefresh: $($Analysis.SOARecord.TimeToZoneRefresh)"
        }
        if ($Analysis.SOARecord.TimeToZoneFailureRetry) {
            Write-Info "TimeToZoneFailureRetry: $($Analysis.SOARecord.TimeToZoneFailureRetry)"
        }
        if ($Analysis.SOARecord.TimeToExpiration) {
            Write-Info "TimeToExpiration: $($Analysis.SOARecord.TimeToExpiration)"
        }
        if ($Analysis.SOARecord.DefaultTTL) {
            Write-Info "DefaultTTL: $($Analysis.SOARecord.DefaultTTL)"
        }
    }
    
    # Primary CDN Information
    Write-Info "`n--- PRIMARY CDN ---" -Color Cyan
    if ($Analysis.PrimaryCDN) {
        Write-Info "Primary CDN: $($Analysis.PrimaryCDN)" -Color Green
    } else {
        Write-Info "Primary CDN: Not detected" -Color Yellow
    }
    if ($Analysis.EdgeLocation -and $Analysis.EdgeLocation -ne 'Unknown') {
        Write-Info "CDN Edge Location: $($Analysis.EdgeLocation)"
    }
    
    # Other CDNs Information
    if ($Analysis.OtherCDNs -and $Analysis.OtherCDNs.Count -gt 0) {
        Write-Info "`n--- OTHER CDNS DETECTED ---" -Color Cyan
        foreach ($cdn in $Analysis.OtherCDNs) {
            Write-Info "  - $cdn" -Color Green
        }
    }
    
    # DDoS Protection Information
    Write-Info "`n--- DDoS Protection Information ---" -Color Cyan
    if ($Analysis.DDoSProviders -and $Analysis.DDoSProviders.Count -gt 0) {
        Write-Info "DDoS Protection Providers: $($Analysis.DDoSProviders -join ', ')" -Color Green
    } else {
        Write-Info "DDoS Protection: Not detected" -Color Yellow
    }
    
    # Origin Information
    Write-Info "`n--- Origin Information ---" -Color Cyan
    if ($Analysis.OriginInfo -and $Analysis.OriginInfo.Count -gt 0) {
        foreach ($origin in $Analysis.OriginInfo) {
            Write-Info "Origin Provider: $($origin.Provider)" -Color Green
            Write-Info "Origin Type: $($origin.Type)" -Color Green
            Write-Info "Origin Category: $($origin.Category)" -Color Green
            Write-Info "Detected From: $($origin.MatchedOn)" -Color Gray
            Write-Info ""
        }
    } else {
        Write-Info "Origin Type: Traditional Web Hosting / Custom Infrastructure" -Color Yellow
        Write-Info "Origin Category: Unknown / Self-Hosted" -Color Yellow
    }
    
    # HTTP Response Info
    if ($Analysis.Response) {
        Write-Info "`n--- HTTP Response Information ---" -Color Cyan
        Write-Info "HTTP Status: $($Analysis.Response.StatusCode)"
        Write-Info "HTTP Version: $($Analysis.Response.ProtocolVersion)"
        Write-Info "Latency: $($Analysis.Response.ElapsedMilliseconds) ms"
        
        # Cache Information
        if ($Analysis.CacheStatus) {
            Write-Info "`n--- Cache Information ---" -Color Cyan
            Write-Info "Cache Status: $($Analysis.CacheStatus.Status)"
            Write-Info "Cache Control: $($Analysis.CacheStatus.CacheControl)"
        }
        
        # Compression Information
        if ($Analysis.CompressionInfo) {
            Write-Info "`n--- Compression Information ---" -Color Cyan
            Write-Info "Content-Encoding: $($Analysis.CompressionInfo.ContentEncoding)"
            if ($Analysis.CompressionInfo.OriginalSize -gt 0) {
                Write-Info "Uncompressed Size: $($Analysis.CompressionInfo.OriginalSize) bytes"
                Write-Info "Compressed Size: $($Analysis.CompressionInfo.CompressedSize) bytes"
                Write-Info "Compression Ratio: $($Analysis.CompressionInfo.CompressionRatio)%"
            }
        }
        
        # TLS Information
        if ($Analysis.TLSInfo) {
            Write-Info "`n--- TLS/SSL Certificate Information ---" -Color Cyan
            Write-Info "TLS Issuer: $($Analysis.TLSInfo.Issuer)"
            Write-Info "TLS Subject: $($Analysis.TLSInfo.Subject)"
            Write-Info "TLS Expires: $($Analysis.TLSInfo.NotAfter) ($($Analysis.TLSInfo.DaysLeft) days left)"
        }
        
        # Headers
        Write-Info "`n--- HTTP Headers ---" -Color Cyan
        if ($Analysis.Response.Headers -and $Analysis.Response.Headers.Count -gt 0) {
            # Display headers in table format
            $headerTable = @()
            try {
                $Analysis.Response.Headers.GetEnumerator() | ForEach-Object {
                    $headerTable += [PSCustomObject]@{
                        Key = $_.Key
                        Value = $_.Value
                    }
                }
            }
            catch {
                # Fallback for different header formats
                $Analysis.Response.Headers.Keys | ForEach-Object {
                    $headerTable += [PSCustomObject]@{
                        Key = $_
                        Value = $Analysis.Response.Headers[$_]
                    }
                }
            }
            $headerTable | Format-Table -AutoSize | Out-String | Write-Host
            
            # Show custom/interesting headers separately
            $customHeaders = @()
            $Analysis.Response.Headers.GetEnumerator() | ForEach-Object {
                if ($_.Key -match '^x-|^cf-|^server$|^via$') {
                    $customHeaders += "$($_.Key): $($_.Value)"
                }
            }
            if ($customHeaders.Count -gt 0) {
                Write-Info "`nCustom Headers:" -Color Cyan
                foreach ($header in $customHeaders) {
                    Write-Info "  $header"
                }
            }
        }
        
        # Azure Front Door POP
        if ($Analysis.AzureFrontDoorPOP) {
            Write-Info "`n--- Azure Front Door Information ---" -Color Cyan
            Write-Info "Azure Front Door POP: $($Analysis.Response.Headers['x-azure-ref'])"
            Write-Info "Decoded AFD POP Location: $($Analysis.AzureFrontDoorPOP)" -Color Green
            
            # Additional Azure headers
            if ($Analysis.Response.Headers['X-Azure-FDID']) {
                Write-Info "Front Door Profile ID: $($Analysis.Response.Headers['X-Azure-FDID'])"
            }
            if ($Analysis.Response.Headers['X-MS-Request-ID']) {
                Write-Info "Request ID: $($Analysis.Response.Headers['X-MS-Request-ID'])"
            }
            if ($Analysis.Response.Headers['X-Azure-RequestChain']) {
                Write-Info "Request Chain: $($Analysis.Response.Headers['X-Azure-RequestChain'])"
            }
        }
        
        # Azure API Management Detection
        if ($script:SubscriptionKey -or $Analysis.Response.Headers['ocp-apim-trace-location'] -or 
            $Analysis.Response.Headers['Ocp-Apim-Trace-Location'] -or
            ($Analysis.Response.StatusCode -eq 401 -and $Analysis.Response.Headers['WWW-Authenticate'] -match 'subscription')) {
            Write-Info "`n--- Azure API Management (APIM) ---" -Color Cyan
            Write-Info "APIM Detected: Yes" -Color Green
            Write-Info "Authentication: Subscription Key (ocp-apim-subscription-key)" -Color Gray
            if ($Analysis.Response.Headers['ocp-apim-trace-location']) {
                Write-Info "Trace Location: $($Analysis.Response.Headers['ocp-apim-trace-location'])"
            }
        }
        
        # 403 Forbidden Diagnosis
        if ($Analysis.Response.StatusCode -eq 403) {
            Write-Info "`n--- 403 Forbidden Diagnosis ---" -Color Yellow
            $possibleCauses = @()
            
            # Check for WAF block indicators
            if ($Analysis.Response.Headers['X-Azure-Ref'] -or $Analysis.Response.Headers['x-azure-ref']) {
                $possibleCauses += "Azure Front Door WAF policy block"
            }
            if ($Analysis.Response.Headers['X-Ms-Forbidden-Reason']) {
                $possibleCauses += "Reason: $($Analysis.Response.Headers['X-Ms-Forbidden-Reason'])"
            }
            
            # Check for APIM auth failure
            if ($script:SubscriptionKey) {
                $possibleCauses += "APIM subscription key may be invalid or expired"
                $possibleCauses += "APIM subscription may not have access to this API"
            } else {
                $possibleCauses += "Missing API subscription key (ocp-apim-subscription-key)"
            }
            
            # Check for IP restriction
            $possibleCauses += "IP address restriction or geo-blocking"
            $possibleCauses += "Origin server access control"
            
            # Check for rate limiting
            if ($Analysis.Response.Headers['Retry-After']) {
                $possibleCauses += "Rate limiting - Retry after: $($Analysis.Response.Headers['Retry-After']) seconds"
            }
            if ($Analysis.Response.Headers['X-RateLimit-Remaining']) {
                $possibleCauses += "Rate limit remaining: $($Analysis.Response.Headers['X-RateLimit-Remaining'])"
            }
            
            Write-Info "Possible causes:" -Color Yellow
            foreach ($cause in $possibleCauses) {
                Write-Info "  • $cause"
            }
        }
        
        # WAF Challenge Detection
        $wafChallengeDetected = $false
        $wafProvider = ""
        $wafIndicators = @()
        
        # AWS WAF Challenge
        if ($Analysis.Response.Headers['x-amzn-waf-action'] -match 'challenge|captcha|block') {
            $wafChallengeDetected = $true
            $wafProvider = "AWS WAF"
            $wafIndicators += "x-amzn-waf-action: $($Analysis.Response.Headers['x-amzn-waf-action'])"
        }
        
        # Cloudflare Challenge
        if ($Analysis.Response.Headers['cf-mitigated'] -or 
            $Analysis.Response.Headers['cf-chl-bypass'] -or
            ($Analysis.Response.StatusCode -eq 403 -and $Analysis.Response.Headers['cf-ray'])) {
            $wafChallengeDetected = $true
            $wafProvider = "Cloudflare"
            if ($Analysis.Response.Headers['cf-mitigated']) {
                $wafIndicators += "cf-mitigated: $($Analysis.Response.Headers['cf-mitigated'])"
            }
        }
        
        # Azure WAF / Front Door Challenge
        if (($Analysis.Response.StatusCode -in @(403, 429)) -and $Analysis.Response.Headers['x-azure-ref']) {
            $wafChallengeDetected = $true
            $wafProvider = "Azure Front Door WAF"
            $wafIndicators += "Blocked request with x-azure-ref present"
        }
        
        # Akamai Bot Manager
        if ($Analysis.Response.Headers['x-akamai-session-info'] -match 'bot' -or
            $Analysis.Response.Headers['akamai-grn']) {
            $wafChallengeDetected = $true
            $wafProvider = "Akamai Bot Manager"
        }
        
        # Incapsula/Imperva
        if ($Analysis.Response.Headers['x-iinfo'] -or 
            ($Analysis.Response.StatusCode -eq 403 -and $Analysis.Response.Headers['x-cdn'] -match 'incapsula|imperva')) {
            $wafChallengeDetected = $true
            $wafProvider = "Imperva/Incapsula"
        }
        
        # Generic indicators
        if ($Analysis.Response.Headers['X-Cache'] -match 'Error' -and $Analysis.Response.StatusCode -eq 202) {
            if (-not $wafChallengeDetected) {
                $wafChallengeDetected = $true
                $wafProvider = "Unknown WAF"
                $wafIndicators += "202 status with cache error (typical challenge pattern)"
            }
        }
        
        # Small response body with non-200 status often indicates challenge page
        $contentLength = 0
        if ($Analysis.Response.Headers['Content-Length']) {
            try { $contentLength = [int]$Analysis.Response.Headers['Content-Length'] } catch {}
        }
        if ($contentLength -gt 0 -and $contentLength -lt 5000 -and $Analysis.Response.StatusCode -in @(200, 202, 403, 429)) {
            if ($wafChallengeDetected) {
                $wafIndicators += "Small response body ($contentLength bytes) - likely challenge/interstitial page"
            }
        }
        
        if ($wafChallengeDetected) {
            Write-Info "`n--- WAF Challenge Detected ---" -Color Yellow
            Write-Info "⚠ WARNING: This response appears to be a WAF challenge page, not the actual site content" -Color Yellow
            Write-Info "WAF Provider: $wafProvider" -Color Yellow
            if ($wafIndicators.Count -gt 0) {
                Write-Info "Indicators:" -Color Gray
                foreach ($indicator in $wafIndicators) {
                    Write-Info "  • $indicator" -Color Gray
                }
            }
            Write-Info "`nNote: Security headers and content analysis below may be incomplete." -Color Yellow
            Write-Info "The actual site likely has additional security headers after passing the challenge." -Color Gray
            Write-Info "To see real headers, use a browser with DevTools (F12 → Network tab)." -Color Gray
        }
        
        # Security Headers Audit
        Write-Info "`n--- Security Headers Audit ---" -Color Cyan
        
        if ($wafChallengeDetected) {
            Write-Info "[!] Results may be incomplete due to WAF challenge response" -Color Yellow
        }
        
        $missingHeaders = @()
        $presentHeaders = @()
        
        foreach ($secHeader in $script:RecommendedSecurityHeaders) {
            $headerPresent = $false
            foreach ($key in $Analysis.Response.Headers.Keys) {
                if ($key -ieq $secHeader.Name) {
                    $headerPresent = $true
                    break
                }
            }
            
            if ($headerPresent) {
                $presentHeaders += $secHeader
            } else {
                $missingHeaders += $secHeader
            }
        }
        
        if ($presentHeaders.Count -gt 0) {
            Write-Info "Present Security Headers:" -Color Green
            foreach ($h in $presentHeaders) {
                Write-Info "  ✓ $($h.Name)" -Color Green
            }
        }
        
        if ($missingHeaders.Count -gt 0) {
            Write-Info "Missing Security Headers:" -Color Yellow
            foreach ($h in $missingHeaders) {
                $color = switch ($h.Severity) {
                    'High' { 'Red' }
                    'Medium' { 'Yellow' }
                    default { 'Gray' }
                }
                Write-Info "  ✗ $($h.Name) [$($h.Severity)] - $($h.Description)" -Color $color
            }
        } else {
            Write-Info "All recommended security headers are present!" -Color Green
        }
    } else {
        Write-Info "`n--- HTTP Response Information ---" -Color Cyan
        Write-Info "[ERROR] No HTTP response received. The request may have failed or timed out." -Color Red
        Write-Info "Check if the URL requires authentication or a subscription key." -Color Yellow
    }
    
    # Redirect Chain
    if ($Analysis.RedirectChain -and $Analysis.RedirectChain.Count -gt 1) {
        Write-Info "`n--- Redirect Chain ---" -Color Cyan
        foreach ($redirect in $Analysis.RedirectChain) {
            Write-Info "$($redirect.StatusCode) -> $($redirect.Url)"
        }
        Write-Info "Final URL: $($Analysis.RedirectChain[-1].Url)"
    }
}

# Main execution
try {
    # Validate URL parameter
    if (-not $Url) {
        Write-Error "URL parameter is required. Usage: .\CheckCDNInfov2.ps1 -Url 'https://example.com'"
        exit 1
    }
    
    Write-Info "=== CDN and Infrastructure Analysis ===" -Color Cyan
    Write-Info "Target URL: $Url" -Color Green
    
    if ($SkipGeo) {
        Write-Info "Geolocation lookups disabled (-SkipGeo)" -Color Yellow
    } else {
        Write-Info "Using cached geolocation lookups to prevent rate limiting" -Color Gray
    }
    
    Write-Warning "Depending on how the site is structured, some URLs may take longer than others to inspect"
    
    # Check if URL points to a specific file or if file analysis is forced
    # File analysis functionality has been removed
    
    # Analyze main URL (always run this for comprehensive analysis)
    Write-Verbose "Starting main URL analysis..."
    $mainAnalysis = Analyze-SingleUrl -Url $Url -IsMainUrl $true
    Write-Verbose "Main URL analysis completed"
    
    Show-UrlAnalysis -Analysis $mainAnalysis
    
    # Extract and analyze resource URLs (reduced count to prevent rate limiting)
    $resourceUrls = @()
    $cdnsFromUrls = @()
    if ($mainAnalysis.Response -and $mainAnalysis.Response.Content) {
        $allResourceUrls = Get-ResourceUrls -HtmlContent $mainAnalysis.Response.Content -BaseUrl $Url
        # Limit to first 10 resources to reduce API calls and prevent rate limiting
        $resourceUrls = $allResourceUrls | Select-Object -First 10
        
        # Analyze CDNs referenced in URLs within the page content
        $uri = [Uri]$Url
        $baseDomain = $uri.Host -replace '^www\.', ''
        $cdnsFromUrls = Get-CDNsFromURLs -Content $mainAnalysis.Response.Content -BaseDomain $baseDomain
    }
    
    $resourceAnalyses = @()
    $allCDNProviders = @()
    $primaryCDNs = @()
    
    # Collect CDNs from main analysis
    if ($mainAnalysis.PrimaryCDN) { 
        $primaryCDNs += $mainAnalysis.PrimaryCDN
    }
    if ($mainAnalysis.AllCDNProviders) { 
        foreach ($cdn in $mainAnalysis.AllCDNProviders) {
            if ($cdn -and ($cdn -is [string]) -and $cdn.Trim() -ne '') {
                $allCDNProviders += $cdn
            }
        }
    }
    
    foreach ($resourceUrl in $resourceUrls) {
        $resourceAnalysis = Analyze-SingleUrl -Url $resourceUrl -IsMainUrl $false
        $resourceAnalyses += $resourceAnalysis
        # Note: Don't add resource PrimaryCDN to main site's primary CDNs
        # Resources like cdnjs.cloudflare.com are not primary CDNs for the main site
        if ($resourceAnalysis.AllCDNProviders) {
            foreach ($cdn in $resourceAnalysis.AllCDNProviders) {
                if ($cdn -and ($cdn -is [string]) -and $cdn.Trim() -ne '') {
                    $allCDNProviders += $cdn
                }
            }
        }
    }
    
    # Simple resource summary without detailed output
    if ($resourceAnalyses.Count -gt 0) {
        $resourcesWithCDN = ($resourceAnalyses | Where-Object { $_.AllCDNProviders -and $_.AllCDNProviders.Count -gt 0 }).Count
        # Resource analysis summary removed per user request
    }
    
    # Final summary
    $uniquePrimaryCDNs = $primaryCDNs | Where-Object { $_ -and ($_ -is [string]) -and $_.Trim() -ne '' } | Select-Object -Unique
    $uniqueAllCDNs = $allCDNProviders | Where-Object { $_ -and ($_ -is [string]) -and $_.Trim() -ne '' } | Select-Object -Unique
    $uniqueOtherCDNs = $uniqueAllCDNs | Where-Object { $_ -notin $uniquePrimaryCDNs }
    
    $allDDoSProviders = @()
    if ($mainAnalysis.DDoSProviders) {
        $allDDoSProviders += $mainAnalysis.DDoSProviders
    }
    foreach ($resourceAnalysis in $resourceAnalyses) {
        if ($resourceAnalysis.DDoSProviders) {
            $allDDoSProviders += $resourceAnalysis.DDoSProviders
        }
    }
    $uniqueDDoS = $allDDoSProviders | Where-Object { $_ -and ($_ -is [string]) -and $_.Trim() -ne '' } | Select-Object -Unique
    
    $allOrigins = @()
    if ($mainAnalysis.OriginInfo) {
        $allOrigins += $mainAnalysis.OriginInfo
    }
    foreach ($resourceAnalysis in $resourceAnalyses) {
        if ($resourceAnalysis.OriginInfo) {
            $allOrigins += $resourceAnalysis.OriginInfo
        }
    }
    $uniqueOrigins = $allOrigins | Group-Object Provider, Type, Category | ForEach-Object { $_.Group[0] }
    
    Write-Info "`n=== PRIMARY CDN(S) ===" -Color Cyan
    if ($uniquePrimaryCDNs.Count -gt 0) {
        foreach ($cdn in $uniquePrimaryCDNs) {
            Write-Info "  - $cdn" -Color Green
        }
    } else {
        Write-Info "  No primary CDN detected" -Color Yellow
    }
    
    if ($uniqueOtherCDNs.Count -gt 0) {
        Write-Info "`n=== OTHER CDNS DETECTED ===" -Color Cyan
        foreach ($cdn in $uniqueOtherCDNs) {
            Write-Info "  - $cdn" -Color Green
        }
    }
    
    # Show CDNs found in page URLs
    if ($cdnsFromUrls.Count -gt 0) {
        Write-Info "`n=== CDNS REFERENCED IN PAGE URLS ===" -Color Cyan
        $cdnGroups = $cdnsFromUrls | Group-Object CDN
        foreach ($group in $cdnGroups) {
            Write-Info "  - $($group.Name)" -Color Green
            $domainGroups = $group.Group | Group-Object Domain
            foreach ($domainGroup in $domainGroups) {
                $urlCount = $domainGroup.Count
                Write-Info "    |- $($domainGroup.Name) ($urlCount references)" -Color Gray
            }
        }
    }
    
    Write-Info "`n=== FINAL DDoS PROTECTION SUMMARY ===" -Color Cyan
    if ($uniqueDDoS.Count -gt 0) {
        foreach ($ddos in $uniqueDDoS) {
            Write-Info "  - $ddos" -Color Green
        }
    } else {
        Write-Info "  No DDoS protection detected" -Color Yellow
    }
    
    Write-Info "`n=== FINAL ORIGIN SUMMARY ===" -Color Cyan
    if ($uniqueOrigins.Count -gt 0) {
        foreach ($origin in $uniqueOrigins) {
            # Simplify Azure service names to just "Azure"
            $displayProvider = if ($origin.Provider -like "*Azure*" -or $origin.Type -like "*Azure*") {
                "Azure"
            } else {
                $origin.Provider
            }
            Write-Info "  - ${displayProvider}: $($origin.Type) ($($origin.Category))" -Color Green
        }
    } else {
        Write-Info "  Traditional Web Hosting / Custom Infrastructure" -Color Yellow
    }
    
    Write-Info "`nAnalysis completed successfully!" -Color Green
}
catch {
    Write-Error "Fatal error during analysis" $_.Exception.Message
    exit 1
}
