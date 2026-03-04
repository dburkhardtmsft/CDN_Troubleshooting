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
    'BNA'='Nashville'; 'BNE'='Brisbane'; 'BOG'='Bogota'; 'BOM'='Mumbai'; 'BOS'='Boston'
    'BRU'='Brussels'; 'BUD'='Budapest'; 'BUE'='Buenos Aires'; 'BUH'='Bucharest'; 'BY'='Boydton, Virginia'
    'CAI'='Cairo'; 'CBR'='Canberra'; 'CH'='Chicago'; 'CHI'='Chicago'; 'CLT'='Charlotte'
    'MWH'='Moses Lake'; 'CPH'='Copenhagen'; 'CPQ'='Campinas'; 'CO'='Quincy, WA'; 'CPT'='Cape Town'
    'CVG'='Cincinnati'; 'CWL'='Cardiff'; 'CYS'='Cheyenne'; 'DAL'='Dallas'; 'DUB'='Dublin'
    'DEL'='Delhi'; 'DFW'='Dallas/Fort Worth'; 'DM'='Des Moines'; 'DSM'='Des Moines'; 'DEN'='Denver'
    'DOH'='Doha'; 'DTT'='Detroit'; 'DUS'='Dusseldorf'; 'DXB'='Dubai'; 'EWR'='Newark'
    'FOR'='Fortaleza'; 'FRA'='Frankfurt'; 'SAO'='Sao Paulo'; 'GVA'='Geneva'; 'GVX'='Gavle'
    'HEL'='Helsinki'; 'HKG'='Hong Kong'; 'HNL'='Honolulu'; 'HOU'='Houston'; 'HYD'='Hyderabad'
    'IAD'='Ashburn, Virginia'; 'IST'='Istanbul'; 'JAX'='Jacksonville'; 'JGA'='Jamnagar'
    'JHB'='Johor Bahru'; 'JKT'='Jakarta'; 'JNB'='Johannesburg'; 'KUL'='Kuala Lumpur'; 'LAD'='Luanda'
    'LAS'='Las Vegas'; 'LAX'='Los Angeles'; 'LIS'='Lisbon'; 'LON'='London'; 'LOS'='Lagos'
    'MMA'='Malmo'; 'MAD'='Madrid'; 'MAN'='Manchester'; 'MEL'='Melbourne'; 'MEX'='Mexico City'
    'MIA'='Miami'; 'MIL'='Milan'; 'MNL'='Manila'; 'MRS'='Marseille'; 'MSP'='Minneapolis--Saint Paul'
    'MUC'='Munich'; 'NAG'='Nagpur'; 'NBO'='Nairobi'; 'NYC'='New York City'; 'ORD'='Chicago'
    'OSA'='Osaka'; 'OSL'='Oslo'; 'PAO'='Palo Alto'; 'PAR'='Paris'; 'PDX'='Portland, Oregon'
    'PER'='Perth'; 'PHL'='Philadelphia'; 'PHX'='Phoenix'; 'PNQ'='Pune'; 'PRG'='Prague'
    'PUS'='Busan'; 'QRO'='Queretaro City'; 'RBA'='Rabat'; 'RIO'='Rio de Janeiro'; 'ROM'='Rome'
    'SCL'='Santiago de Chile'; 'SEL'='Seoul'; 'SG'='Singapore'; 'SGN'='Ho Chi Minh City'
    'SJC'='San Jose, California'; 'SLA'='Seoul'; 'SLC'='Salt Lake City'; 'SN'='San Antonio'
    'SOF'='Sofia'; 'SEA'='Seattle'; 'STO'='Stockholm'; 'SVG'='Stavanger'; 'SYD'='Sydney'
    'TEB'='Teterboro'; 'TLV'='Tel Aviv'; 'TPE'='Taipei'; 'TYO'='Tokyo'; 'VA'='Ashburn, Virginia'
    'VIE'='Vienna'; 'WAW'='Warsaw'; 'YMQ'='Montreal'; 'YQB'='Quebec City'; 'WST'='Seattle'
    'YTO'='Toronto'; 'YVR'='Vancouver'; 'ZAG'='Zagreb'; 'ZRH'='Zurich'
}

# Known TLS Interception / MITM Certificate Issuers
$script:HighConfidenceMITMIssuers = @(
    'Palo Alto', 'PAN-', 'Fortinet', 'FortiGate', 'Fortigate',
    'Check Point', 'Checkpoint', 'SonicWall', 'Sonic Wall',
    'Sophos', 'Barracuda', 'WatchGuard', 'Juniper', 'Cisco Umbrella',
    'Cisco IronPort', 'Meraki', 'Zscaler', 'zscaler', 'ZS-',
    'Netskope', 'Symantec', 'BlueCoat', 'Blue Coat', 'ProxySG', 'Broadcom',
    'McAfee Web Gateway', 'Skyhigh', 'iboss', 'Menlo Security',
    'Websense', 'Forcepoint', 'Squid', 'SSL Inspection', 'DPI-SSL',
    'Deep Packet Inspection', 'Transparent Proxy'
)

$script:WeakMITMIssuers = @(
    'Corporate Root', 'Enterprise Root', 'Company Root',
    'Internal CA', 'Proxy CA', 'Inspection CA',
    'DO_NOT_TRUST', 'FiddlerRoot', 'mitmproxy', 'Charles Proxy',
    'BurpSuite', 'ESET SSL Filter', 'MITM'
)

# Known Middlebox / NVA Hostname Patterns (for traceroute hop analysis)
$script:MiddleboxHopPatterns = @(
    # Firewall vendors
    'paloalto', 'pan-', 'fortinet', 'fortigate', 'checkpoint', 'sonicwall',
    'sophos', 'barracuda', 'watchguard', 'juniper-fw', 'cisco-fw', 'meraki',
    # NVA / proxy patterns
    'nva', 'firewall', 'fw-', '-fw-', '-fw\.', 'proxy', 'squid',
    'waf-', '-waf-', 'inspection', 'filter', 'guard',
    # SD-WAN patterns
    'sdwan', 'sd-wan', 'viptela', 'velocloud', 'silverpeak', 'citrix-sd',
    # Cloud security gateways
    'zscaler', 'zs-', 'netskope', 'iboss', 'menlo', 'bluecoat',
    # VPN patterns
    'vpn-', '-vpn-', 'tunnel', 'ipsec', 'sslvpn',
    # WAN optimizer
    'riverbed', 'steelhead', 'wan-opt', 'wanopt'
)

# Proxy-Indicating Response Headers
$script:ProxyIndicatorHeaders = @(
    'Via',
    'X-Forwarded-For',
    'X-Forwarded-Host',
    'X-Forwarded-Proto',
    'X-Forwarded-Server',
    'Forwarded',
    'X-BlueCoat-Via',
    'X-Zscaler-TransactionID',
    'X-Zscaler-Via',
    'X-Zscaler',
    'X-Squid-Error',
    'X-Cache-Lookup',
    'X-Proxy-ID',
    'X-Proxy-Cache',
    'Proxy-Connection',
    'Proxy-Agent',
    'X-Authenticated-User',
    'X-UIDH',
    'X-MSISDN',
    'X-ISA-ID',
    'ISA-Server',
    'X-Forwarded-By',
    'X-imforwards',
    'X-Forwarded-Port'
)

# Known SASE/SSE DNS Patterns (CNAMEs or hostnames that indicate a security service in the path)
$script:SASEDnsPatterns = @(
    @{ Name = 'Netskope';               Patterns = @('goskope.com', 'netskope.com', 'npa.goskope.com') }
    @{ Name = 'Zscaler';                Patterns = @('zscaler.net', 'zscalertwo.net', 'zscalerthree.net', 'zscloud.net', 'zpa.zscaler.com') }
    @{ Name = 'Palo Alto Prisma';       Patterns = @('gpcloudservice.com', 'prismaaccess.com', 'paloaltonetworks.com') }
    @{ Name = 'Cisco Umbrella';         Patterns = @('sig.umbrella.com', 'swg.umbrella.com', 'opendns.com') }
    @{ Name = 'Forcepoint';             Patterns = @('forcepoint.net', 'mailcontrol.com') }
    @{ Name = 'Symantec/Broadcom WSS';  Patterns = @('messagelabs.com', 'symantec.com', 'threatpulse.com') }
    @{ Name = 'McAfee/Skyhigh';         Patterns = @('mvision.mcafee.com', 'saasprotection.com', 'skyhighsecurity.com', 'mcafee.net') }
    @{ Name = 'iboss';                  Patterns = @('iboss.com', 'ibosscloud.com', 'ibossconnect.com') }
    @{ Name = 'Menlo Security';         Patterns = @('menlosecurity.com', 'safebrowsing.menlosecurity.com') }
    @{ Name = 'Cloudflare Gateway';     Patterns = @('cloudflare-gateway.com', 'cf-gateway.com') }
)

# Known SASE/SSE IP Org/ASN Patterns (for whois-based detection)
$script:SASEIPOrgPatterns = @(
    @{ Name = 'Netskope';               Patterns = @('Netskope', 'NETSKOPE') }
    @{ Name = 'Zscaler';                Patterns = @('Zscaler', 'ZSCALER') }
    @{ Name = 'Palo Alto Prisma';       Patterns = @('Palo Alto Networks', 'PANW') }
    @{ Name = 'Cisco Umbrella';         Patterns = @('OpenDNS', 'Cisco Umbrella', 'OPENDNS') }
    @{ Name = 'Forcepoint';             Patterns = @('Forcepoint') }
    @{ Name = 'iboss';                  Patterns = @('iboss', 'IBOSS') }
    @{ Name = 'Menlo Security';         Patterns = @('Menlo Security') }
)

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

function Write-Err {
    param([string]$Message, [string]$ErrorDetail = '')
    $fullMessage = if ($ErrorDetail) { "$Message - $ErrorDetail" } else { $Message }
    Write-Host "[ERROR] $fullMessage" -ForegroundColor Red
}

$script:SupportsLegacyParsing = $PSVersionTable.PSVersion.Major -lt 6

function Invoke-WebRequestCompat {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Parameters
    )

    $invokeParams = @{}
    foreach ($key in $Parameters.Keys) {
        $invokeParams[$key] = $Parameters[$key]
    }

    if ($script:SupportsLegacyParsing) {
        $invokeParams['UseBasicParsing'] = $true
    } elseif ($invokeParams.ContainsKey('UseBasicParsing')) {
        $invokeParams.Remove('UseBasicParsing')
    }

    return Invoke-WebRequest @invokeParams
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
        $geoData = Invoke-RestMethod -Uri $geoUrl -TimeoutSec 10 -ErrorAction Stop
        
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
    $baseParams = @{
        Uri = $Uri
        Headers = $headers
        Method = $Method
        TimeoutSec = $TimeoutSec
        ErrorAction = 'Stop'
    }

    try {
        $response = Invoke-WebRequestCompat -Parameters $baseParams
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
                $retryParams = $baseParams.Clone()
                $retryParams['Method'] = 'GET'
                $retryParams['TimeoutSec'] = 5
                $response = Invoke-WebRequestCompat -Parameters $retryParams
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
                $shortParams = $baseParams.Clone()
                $shortParams['TimeoutSec'] = 5
                $response = Invoke-WebRequestCompat -Parameters $shortParams
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
                    try {
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
                    }
                    finally {
                        if ($httpClient) { $httpClient.Dispose() }
                    }
                    
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
            $whoisData = Invoke-RestMethod -Uri $whoisUrl -TimeoutSec 5 -ErrorAction Stop
            
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
            $response = Invoke-WebRequestCompat -Parameters @{
                Uri = $currentUrl
                MaximumRedirection = 0
                ErrorAction = 'SilentlyContinue'
            }
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
    
    $tcpClient = $null
    $sslStream = $null
    try {
        $uri = [Uri]$Url
        $tcpClient = [System.Net.Sockets.TcpClient]::new()
        $connectTask = $tcpClient.ConnectAsync($uri.Host, 443)
        if (-not $connectTask.Wait(5000)) {
            throw "TLS connect to $($uri.Host) timed out after 5 seconds"
        }

        $sslStream = New-Object Net.Security.SslStream($tcpClient.GetStream(), $false, {$true})
        $sslStream.ReadTimeout = 5000
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
    catch {
        Write-Warning "Failed to get TLS info for $Url`: $($_.Exception.Message)"
        return $null
    }
    finally {
        if ($sslStream) { $sslStream.Dispose() }
        if ($tcpClient) { $tcpClient.Close(); $tcpClient.Dispose() }
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

# ============================================================
# MIDDLEMAN / MIDDLEBOX DETECTION FUNCTIONS
# ============================================================

function Test-DnsSteering {
    param(
        [string]$Hostname,
        [string]$PublicResolver = '1.1.1.1'
    )

    $result = [PSCustomObject]@{
        SystemResolver         = $null
        PublicResolver         = $PublicResolver
        SystemAddresses        = @()
        PublicAddresses        = @()
        SystemQuerySucceeded   = $false
        PublicQuerySucceeded   = $false
        DivergenceDetected     = $false
        Notes                  = @()
    }

    try {
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.ServerAddresses.Count -gt 0 }
        if ($dnsServers) {
            $result.SystemResolver = $dnsServers[0].ServerAddresses[0]
        }
    }
    catch {
        $result.Notes += "Could not determine system DNS resolver: $($_.Exception.Message)"
    }

    $resolveRecords = {
        param($server)
        $addresses = New-Object System.Collections.Generic.List[string]
        $success = $false
        # Only query A records (IPv4) for the divergence comparison.
        # Including AAAA causes false positives because many corporate DNS resolvers
        # return additional IPv6 addresses that public resolvers like 1.1.1.1 do not,
        # making every enterprise network appear to have DNS steering even when clean.
        foreach ($recordType in @('A')) {
            $params = @{ Name = $Hostname; Type = $recordType; ErrorAction = 'Stop' }
            if ($server) { $params['Server'] = $server }
            try {
                $records = Resolve-DnsName @params
                foreach ($rec in $records) {
                    if ($rec.IPAddress) { [void]$addresses.Add($rec.IPAddress) }
                }
                $success = $true
            }
            catch {
                $msg = $_.Exception.Message
                $dnsNotFound = $msg -match 'DNS name does not exist' -or $msg -match 'Name does not exist' -or $msg -match 'NXDOMAIN'
                if ($dnsNotFound) {
                    $success = $true
                } else {
                    throw
                }
            }
        }
        $sorted = $addresses.ToArray()
        if ($sorted.Count -gt 0) {
            $sorted = $sorted | Sort-Object -Unique
        } else {
            $sorted = @()
        }
        return @{ Success = $success; Addresses = $sorted }
    }

    try {
        $sysResult = & $resolveRecords $null
        if ($sysResult.Success) {
            $result.SystemQuerySucceeded = $true
            $result.SystemAddresses = $sysResult.Addresses
        }
    }
    catch {
        $result.Notes += "System resolver query failed: $($_.Exception.Message)"
    }

    try {
        $publicResult = & $resolveRecords $PublicResolver
        if ($publicResult.Success) {
            $result.PublicQuerySucceeded = $true
            $result.PublicAddresses = $publicResult.Addresses
        }
    }
    catch {
        $result.Notes += "Public resolver $PublicResolver query failed: $($_.Exception.Message)"
    }

    if ($result.SystemQuerySucceeded -and $result.PublicQuerySucceeded) {
        $sysSet = @($result.SystemAddresses) | Sort-Object -Unique
        $pubSet = @($result.PublicAddresses) | Sort-Object -Unique
        $diverged = $false
        if ($sysSet.Count -ne $pubSet.Count) {
            $diverged = $true
        } elseif ($sysSet.Count -gt 0) {
            # Compare-Object requires non-empty collections in PS 5.1
            $diverged = (@(Compare-Object -ReferenceObject $sysSet -DifferenceObject $pubSet)).Count -gt 0
        }
        # else: both empty (both NXDOMAIN) => no divergence
        if ($diverged) {
            $result.DivergenceDetected = $true
            $result.Notes += "System resolver returned [$($sysSet -join ', ')], public resolver returned [$($pubSet -join ', ')]"
        }
    }

    return $result
}

function Test-TLSInterception {
    <#
    .SYNOPSIS
        Checks the TLS certificate chain for signs of MITM / TLS inspection.
        A corporate proxy or NVA doing TLS inspection will re-sign traffic
        with its own CA, which differs from the legitimate issuer.
    #>
    param([string]$Url)

    $result = [PSCustomObject]@{
        Intercepted            = $false
        Issuer                 = $null
        Subject                = $null
        MatchedPattern         = $null
        CertificateChain       = @()
        Notes                  = @()
        LeafThumbprint         = $null
        HostnameMatches        = $null
        SslPolicyErrors        = 'None'
        HighConfidenceMatches  = @()
        WeakMatches            = @()
        SubjectAlternativeNames = @()
    }

    if ($Url -notmatch '^https://') { return $result }

    $tcpClient = $null
    $sslStream = $null
    try {
        $uri = [Uri]$Url
        $tcpClient = [System.Net.Sockets.TcpClient]::new()
        $connectTask = $tcpClient.ConnectAsync($uri.Host, 443)
        if (-not $connectTask.Wait(5000)) {
            throw "TLS connect to $($uri.Host) timed out after 5 seconds"
        }

        $policyErrorsRef = [ref][System.Security.Authentication.SslPolicyErrors]::None
        $validationCallback = [Net.Security.RemoteCertificateValidationCallback]{
            param($sender, $certificate, $chain, $sslPolicyErrors)
            $policyErrorsRef.Value = $sslPolicyErrors
            return $true
        }

        $sslStream = New-Object Net.Security.SslStream($tcpClient.GetStream(), $false, $validationCallback)
        $sslStream.AuthenticateAsClient($uri.Host)

        $policyErrors = $policyErrorsRef.Value
        $cert2 = New-Object Security.Cryptography.X509Certificates.X509Certificate2 $sslStream.RemoteCertificate
        $result.Issuer  = $cert2.Issuer
        $result.Subject = $cert2.Subject
        $result.LeafThumbprint = $cert2.Thumbprint
        $result.SslPolicyErrors = $policyErrors.ToString()

        # Extract SAN entries for hostname comparison
        $sanList = @()
        $sanExtension = $cert2.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
        if ($sanExtension) {
            $formattedSan = $sanExtension.Format($false)
            if ($formattedSan) {
                $sanList = ($formattedSan -split ',\s*') | ForEach-Object { $_ -replace '^DNS Name=','' } | Where-Object { $_ }
            }
        }
        $result.SubjectAlternativeNames = $sanList

        $hostnameMatches = $false
        foreach ($san in $sanList) {
            $pattern = '^' + ([regex]::Escape($san).Replace('\*', '.*')) + '$'
            if ($uri.Host -match $pattern) { $hostnameMatches = $true; break }
        }
        if (-not $hostnameMatches) {
            $cn = $cert2.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
            if ($cn) {
                $pattern = '^' + ([regex]::Escape($cn).Replace('\*', '.*')) + '$'
                if ($uri.Host -match $pattern) { $hostnameMatches = $true }
            }
        }
        $result.HostnameMatches = $hostnameMatches
        if (-not $hostnameMatches) {
            $result.WeakMatches += 'Hostname mismatch'
            $result.Notes += "Certificate SAN/CN does not match $($uri.Host)"
        }

        # Walk the chain
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        [void]$chain.Build($cert2)
        foreach ($element in $chain.ChainElements) {
            $result.CertificateChain += [PSCustomObject]@{
                Subject    = $element.Certificate.Subject
                Issuer     = $element.Certificate.Issuer
                Thumbprint = $element.Certificate.Thumbprint
            }
        }

        $issuerText = "$($cert2.Issuer) $($cert2.GetNameInfo('SimpleName',$true))"
        foreach ($pattern in $script:HighConfidenceMITMIssuers) {
            if ($issuerText -match [regex]::Escape($pattern)) {
                $result.HighConfidenceMatches += $pattern
                $result.Intercepted = $true
                if (-not $result.MatchedPattern) { $result.MatchedPattern = $pattern }
            }
        }
        foreach ($pattern in $script:WeakMITMIssuers) {
            if ($issuerText -match [regex]::Escape($pattern)) {
                $result.WeakMatches += $pattern
                if (-not $result.MatchedPattern) { $result.MatchedPattern = $pattern }
            }
        }
        if ($result.HighConfidenceMatches.Count -gt 0) {
            $result.Notes += "Certificate issuer matches known TLS inspection pattern(s): $($result.HighConfidenceMatches -join ', ')"
        } elseif ($result.WeakMatches.Count -gt 0) {
            $result.Notes += "Certificate issuer contains weak MITM indicators: $($result.WeakMatches -join ', ')"
        }

        $wellKnownRoots = @(
            'DigiCert', "Let's Encrypt", 'ISRG', 'Sectigo', 'Comodo',
            'GlobalSign', 'Entrust', 'Baltimore', 'Microsoft', 'Amazon',
            'Google Trust', 'GeoTrust', 'Thawte', 'VeriSign', 'RapidSSL',
            'GoDaddy', 'Starfield', 'USERTrust', 'QuoVadis', 'SwissSign',
            'Buypass', 'Actalis', 'Certum', 'T-TeleSec', 'D-TRUST',
            'IdenTrust', 'SSL.com', 'Trustwave'
        )
        $rootElement = $chain.ChainElements | Select-Object -Last 1
        if ($rootElement) {
            $rootIssuer = $rootElement.Certificate.Issuer
            $isWellKnown = $false
            foreach ($known in $wellKnownRoots) {
                if ($rootIssuer -match [regex]::Escape($known)) {
                    $isWellKnown = $true
                    break
                }
            }
            if (-not $isWellKnown) {
                $result.WeakMatches += "Unknown Root: $rootIssuer"
                $result.Notes += "Root CA '$rootIssuer' is not a well-known public CA"
            }
        }

        if ($policyErrors -ne [System.Security.Authentication.SslPolicyErrors]::None) {
            $result.WeakMatches += "SSL Policy Errors: $policyErrors"
            $result.Notes += "SSL policy errors reported: $policyErrors"
        }
    }
    catch {
        $result.Notes += "TLS interception check error: $($_.Exception.Message)"
    }
    finally {
        if ($sslStream) { $sslStream.Dispose() }
        if ($tcpClient) { $tcpClient.Close(); $tcpClient.Dispose() }
    }

    return $result
}

function Test-ProxyHeaders {
    <#
    .SYNOPSIS
        Inspects HTTP response headers for evidence of a proxy or middlebox
        injecting its own headers.
    #>
    param($Headers)

    $result = [PSCustomObject]@{
        ProxyDetected   = $false
        DetectedHeaders = @()
        Notes           = @()
        HighConfidenceHeaders = @()
        WeakHeaders     = @()
    }

    if (-not $Headers) { return $result }

    # Normalize header access
    $headerKeys = @()
    if ($Headers -is [hashtable]) {
        $headerKeys = $Headers.Keys
    } elseif ($Headers.GetEnumerator) {
        foreach ($h in $Headers.GetEnumerator()) { $headerKeys += $h.Key }
    }

    foreach ($proxyHeader in $script:ProxyIndicatorHeaders) {
        foreach ($key in $headerKeys) {
            if ($key -ieq $proxyHeader) {
                $value = $null
                if ($Headers -is [hashtable]) { $value = $Headers[$key] }
                else { $value = $Headers[$key] }
                $result.DetectedHeaders += [PSCustomObject]@{
                    Header = $key
                    Value  = $value
                }
                $result.ProxyDetected = $true
                if ($key -ieq 'Proxy-Authenticate' -or $key -ieq 'Proxy-Authorization') {
                    $result.HighConfidenceHeaders += $key
                } else {
                    $result.WeakHeaders += $key
                }
            }
        }
    }

    # Check for Via header that indicates intermediate proxies (not CDN)
    foreach ($key in $headerKeys) {
        if ($key -ieq 'Via') {
            $viaValue = if ($Headers -is [hashtable]) { $Headers[$key] } else { $Headers[$key] }
            # Via headers from CDNs are expected; flag non-CDN Via values
            $cdnViaPatterns = @('cloudfront', 'akamai', 'fastly', 'cloudflare', 'varnish', 'vegur', 'Azure')
            $isCDNVia = $false
            foreach ($cvp in $cdnViaPatterns) {
                if ($viaValue -match $cvp) { $isCDNVia = $true; break }
            }
            if (-not $isCDNVia) {
                $result.Notes += "Non-CDN 'Via' header detected: $viaValue -- may indicate an intermediate proxy"
            }
        }
    }

    if ($result.DetectedHeaders.Count -gt 0) {
        $result.Notes += "Found $($result.DetectedHeaders.Count) proxy-indicating header(s) in response"
    }

    return $result
}

function Get-SystemProxyConfiguration {
    <#
    .SYNOPSIS
        Detects system-level proxy configuration on Windows:
        HTTP_PROXY / HTTPS_PROXY env vars, WinINet proxy settings,
        and PAC / WPAD auto-config URLs.
    #>

    $result = [PSCustomObject]@{
        ProxyConfigured  = $false
        EnvProxies       = @()
        WinINetProxy     = $null
        PACUrl           = $null
        WPADEnabled      = $false
        Notes            = @()
    }

    # 1. Environment variables
    $envVars = @('HTTP_PROXY','HTTPS_PROXY','http_proxy','https_proxy','NO_PROXY','no_proxy','ALL_PROXY','all_proxy')
    foreach ($var in $envVars) {
        $val = [Environment]::GetEnvironmentVariable($var)
        if ($val) {
            $result.EnvProxies += [PSCustomObject]@{ Variable = $var; Value = $val }
            $result.ProxyConfigured = $true
        }
    }

    # 2. WinINet proxy settings (registry)
    try {
        $regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $proxyEnable = (Get-ItemProperty -Path $regPath -Name ProxyEnable -ErrorAction SilentlyContinue).ProxyEnable
        $proxyServer = (Get-ItemProperty -Path $regPath -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
        $autoConfigUrl = (Get-ItemProperty -Path $regPath -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL

        if ($proxyEnable -eq 1 -and $proxyServer) {
            $result.WinINetProxy = $proxyServer
            $result.ProxyConfigured = $true
            $result.Notes += "System proxy configured via WinINet: $proxyServer"
        }

        if ($autoConfigUrl) {
            $result.PACUrl = $autoConfigUrl
            $result.ProxyConfigured = $true
            $result.Notes += "PAC auto-config URL configured: $autoConfigUrl"
        }
    }
    catch {
        $result.Notes += "Could not read WinINet proxy settings: $($_.Exception.Message)"
    }

    # 3. WPAD (Web Proxy Auto-Discovery)
    try {
        $wpadResult = Resolve-DnsName -Name 'wpad' -Type A -ErrorAction SilentlyContinue -DnsOnly
        if ($wpadResult) {
            $result.WPADEnabled = $true
            $result.ProxyConfigured = $true
            $result.Notes += "WPAD DNS entry found -- auto-proxy discovery is active (resolves to $($wpadResult.IPAddress -join ', '))"
        }
    }
    catch { }

    # 4. .NET default proxy
    try {
        $defaultProxy = [System.Net.WebRequest]::DefaultWebProxy
        if ($defaultProxy) {
            $testUri = [Uri]'https://www.microsoft.com'
            $proxyUri = $defaultProxy.GetProxy($testUri)
            if ($proxyUri -and $proxyUri.AbsoluteUri -ne $testUri.AbsoluteUri) {
                $result.Notes += ".NET default proxy routes traffic through: $($proxyUri.AbsoluteUri)"
                $result.ProxyConfigured = $true
            }
        }
    }
    catch { }

    return $result
}

function Get-TracerouteAnalysis {
    <#
    .SYNOPSIS
        Runs tracert (ICMP) to the target host with early-abort on all-timeout
        hops, then supplements with a TCP connectivity test via
        Test-NetConnection (port 443). CDN endpoints like Azure Front Door
        typically drop ICMP, so the TCP test is often more useful.
    #>
    param(
        [string]$Hostname,
        [int]$MaxHops = 15,
        [int]$TimeoutMs = 1500,
        [int]$EarlyAbortAfter = 5,         # kill tracert after this many consecutive all-timeout hops
        [int]$Port = 443
    )

    $result = [PSCustomObject]@{
        Hops               = @()
        SuspiciousHops     = @()
        TimeoutHops        = 0
        TotalHops          = 0
        LatencySpikeHop    = $null
        ICMPAborted        = $false
        TCPTest            = $null          # Test-NetConnection result summary
        Notes              = @()
    }

    # ---- ICMP traceroute (with early abort) ----
    Write-Info "  Running ICMP traceroute to $Hostname (max $MaxHops hops, abort after $EarlyAbortAfter consecutive timeouts)..." -Color Gray

    try {
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo.FileName = 'tracert.exe'
        $proc.StartInfo.Arguments = "-d -h $MaxHops -w $TimeoutMs $Hostname"
        $proc.StartInfo.RedirectStandardOutput = $true
        $proc.StartInfo.RedirectStandardError = $true
        $proc.StartInfo.UseShellExecute = $false
        $proc.StartInfo.CreateNoWindow = $true
        [void]$proc.Start()

        $previousLatency = 0
        $consecutiveTimeouts = 0
        $aborted = $false

        # Read stdout line-by-line for early abort
        while (-not $proc.StandardOutput.EndOfStream) {
            $line = $proc.StandardOutput.ReadLine()
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            if ($line -notmatch '^\s*(\d+)\s') { continue }

            $segments = ($line -split '\s{2,}') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            if ($segments.Count -lt 2 -or $segments[0] -notmatch '^\d+$') { continue }

            $hopNumber = [int]$segments[0]
            $lastToken = $segments[-1]
            $ipPattern = '^[0-9A-Fa-f:\.]+(%\d+)?$'

            if ($lastToken -notmatch $ipPattern) {
                # Entire hop timed out (no IP reported)
                $hop = [PSCustomObject]@{
                    Hop = $hopNumber; IP = '*'; HostName = ''
                    AvgLatency = -1; Timeouts = 3
                    Suspicious = $false; Reason = ''
                }
                $result.Hops += $hop
                $result.TimeoutHops++
                $consecutiveTimeouts++

                if ($consecutiveTimeouts -ge $EarlyAbortAfter) {
                    $aborted = $true
                    try { $proc.Kill() } catch {}
                    $result.ICMPAborted = $true
                    $result.Notes += "ICMP traceroute aborted after $EarlyAbortAfter consecutive timeout hops (ICMP likely blocked). Falling back to TCP test."
                    break
                }
                continue
            }

            $ip = $lastToken
            $timingTokens = if ($segments.Count -gt 2) { $segments[1..($segments.Count - 2)] } else { @() }
            $latencies = @()
            $timeoutCount = 0

            foreach ($token in $timingTokens) {
                if ($token -eq '*') {
                    $timeoutCount++
                }
                elseif ($token -match '(\d+)\s*ms') {
                    $latencies += [int]$Matches[1]
                }
                elseif ($token -match '<\s*1\s*ms') {
                    $latencies += 0
                }
            }

            $avgLatency = if ($latencies.Count -gt 0) { [math]::Round(($latencies | Measure-Object -Average).Average, 1) } else { -1 }
            $consecutiveTimeouts = 0

            $hopName = ''
            try {
                $dnsTask = [System.Net.Dns]::GetHostEntryAsync($ip)
                if ($dnsTask.Wait(2000) -and $dnsTask.Status -eq 'RanToCompletion') {
                    if ($dnsTask.Result.HostName -ne $ip) { $hopName = $dnsTask.Result.HostName }
                }
            } catch { }

            $hop = [PSCustomObject]@{
                Hop = $hopNumber; IP = $ip; HostName = $hopName
                AvgLatency = $avgLatency; Timeouts = $timeoutCount
                Suspicious = $false; Reason = ''
            }

            $searchText = "$ip $hopName".ToLower()
            foreach ($pattern in $script:MiddleboxHopPatterns) {
                if ($searchText -match [regex]::Escape($pattern)) {
                    $hop.Suspicious = $true
                    $hop.Reason = "Hostname/IP matches middlebox pattern: $pattern"
                    $result.SuspiciousHops += $hop
                    break
                }
            }

            if ($avgLatency -gt 0 -and $previousLatency -ge 0) {
                $jump = $avgLatency - $previousLatency
                if ($jump -gt 50 -and -not $hop.Suspicious) {
                    $hop.Suspicious = $true
                    $hop.Reason = "Latency spike of ${jump}ms from previous hop (possible inspection delay)"
                    $result.SuspiciousHops += $hop
                }
            }
            if ($avgLatency -ge 0) { $previousLatency = $avgLatency }

            if ($hopNumber -gt 2 -and $ip -match '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)') {
                if (-not $hop.Suspicious) {
                    $hop.Suspicious = $true
                    $hop.Reason = "Private IP at hop $hopNumber -- traffic may traverse an internal NVA/firewall segment"
                    $result.SuspiciousHops += $hop
                }
            }

            $result.Hops += $hop
        }

        # Wait for process to finish if we didn't abort
        if (-not $aborted) {
            if (-not $proc.HasExited) {
                $finished = $proc.WaitForExit(10000)
                if (-not $finished) { try { $proc.Kill() } catch {} }
            }
        }
        try { $proc.Dispose() } catch {}

        $result.TotalHops = $result.Hops.Count

        # Analyse timeout patterns
        $realHops = ($result.Hops | Where-Object { $_.IP -ne '*' }).Count

        if ($realHops -eq 0 -and $result.Hops.Count -gt 0 -and -not $aborted) {
            $result.Notes += "All $($result.Hops.Count) hops timed out -- ICMP is blocked on this network (common for CDN/cloud endpoints). Traceroute is inconclusive."
        } elseif ($realHops -gt 0) {
            # Look for consecutive timeout runs among real hops (selective suppression)
            $seqTimeouts = 0
            foreach ($hop in $result.Hops) {
                if ($hop.Timeouts -eq 3) { $seqTimeouts++ }
                else {
                    if ($seqTimeouts -ge 3) {
                        $result.Notes += "Found $seqTimeouts consecutive timeout hops -- a firewall/NVA may be suppressing ICMP"
                    }
                    $seqTimeouts = 0
                }
            }
            if ($seqTimeouts -ge 3 -and $realHops -gt 0) {
                $result.Notes += "Found $seqTimeouts consecutive timeout hops at end of path -- ICMP-suppressing device likely present"
            }
        }
    }
    catch {
        $result.Notes += "ICMP traceroute failed: $($_.Exception.Message)"
    }

    # ---- TCP connectivity test (Test-NetConnection) ----
    # This works for AFD/CDN endpoints that drop ICMP but respond on TCP 443
    Write-Info "  Running TCP connectivity test to ${Hostname}:${Port}..." -Color Gray
    try {
        $tcpResult = Test-NetConnection -ComputerName $Hostname -Port $Port -InformationLevel Detailed -WarningAction SilentlyContinue
        # Extract SourceAddress IP properly (it's a CIM object, not a string)
        $srcAddr = if ($tcpResult.SourceAddress.IPAddress) { "$($tcpResult.SourceAddress.IPAddress)" } else { "$($tcpResult.SourceAddress)" }
        $ifAlias = $tcpResult.InterfaceAlias
        $result.TCPTest = [PSCustomObject]@{
            RemoteAddress      = "$($tcpResult.RemoteAddress)"
            RemotePort         = $tcpResult.RemotePort
            TcpTestSucceeded   = $tcpResult.TcpTestSucceeded
            InterfaceAlias     = $ifAlias
            SourceAddress      = $srcAddr
            NextHop            = "$($tcpResult.NetRoute.NextHop)"
            ResolvedAddresses  = @($tcpResult.NameResolutionResults | ForEach-Object { "$_" })
            IsVPN              = $false
        }

        # Detect VPN interfaces -- these are on-path middlemen by definition
        $vpnPatterns = @('VPN', 'Tunnel', 'TAP-', 'TUN', 'WireGuard', 'AzVPN', 'Cisco AnyConnect',
                         'GlobalProtect', 'Fortinet', 'OpenVPN', 'ZeroTier', 'Tailscale', 'PANGP',
                         'Juniper', 'Pulse Secure', 'F5 Access', 'SonicWall', 'Zscaler')
        foreach ($vpnPattern in $vpnPatterns) {
            if ($ifAlias -match [regex]::Escape($vpnPattern)) {
                $result.TCPTest.IsVPN = $true
                $result.Notes += "VPN DETECTED: Traffic is routed through VPN interface '$ifAlias'. This is an on-path middlebox that may modify, inspect, or re-encrypt traffic."
                break
            }
        }

        if ($tcpResult.TcpTestSucceeded) {
            $result.Notes += "TCP:${Port} connectivity SUCCEEDED -- ${Hostname} is reachable (remote: $($tcpResult.RemoteAddress), source: ${srcAddr}, interface: ${ifAlias})"
        } else {
            $result.Notes += "TCP:${Port} connectivity FAILED -- ${Hostname} is NOT reachable on port $Port"
        }
    }
    catch {
        $result.Notes += "TCP connectivity test failed: $($_.Exception.Message)"
    }

    return $result
}

function Test-MTUPathDiscovery {
    <#
    .SYNOPSIS
        Probes the path MTU by sending ICMP pings with the Don't Fragment
        bit set at decreasing sizes. MTU problems (caused by VPN tunnels,
        NVAs, or encapsulation) manifest as large-packet black-holing.
    #>
    param([string]$Hostname)

    $result = [PSCustomObject]@{
        MaxMTU         = 0
        StandardMTU    = $false   # true if 1500 works
        ReducedMTU     = $false   # true if only smaller sizes work
        PossibleIssue  = $false
        Notes          = @()
    }

    $sizes = @(1472, 1400, 1300, 1200, 1100, 1000, 500)   # payload sizes (+ 28 bytes IP+ICMP header = total)

    Write-Info "  Testing path MTU to $Hostname..." -Color Gray

    foreach ($size in $sizes) {
        try {
            # -f = Don't Fragment, -n 1 = one packet, -l = size, -w = timeout
            $pingOutput = & ping.exe -f -n 1 -l $size -w 2000 $Hostname 2>&1
            $pingText = $pingOutput -join ' '

            if ($pingText -match 'Reply from' -and $pingText -notmatch 'needs to be fragmented') {
                if ($result.MaxMTU -eq 0) {
                    $result.MaxMTU = $size + 28   # total MTU including IP+ICMP headers
                }
                if ($size -eq 1472) {
                    $result.StandardMTU = $true
                }
                break   # Largest working size found
            }
            elseif ($pingText -match 'needs to be fragmented|Packet needs to be fragmented') {
                # DF bit caused rejection -- MTU is smaller than this size
                continue
            }
            elseif ($pingText -match 'Request timed out|Destination host unreachable|General failure') {
                # May be black-holed -- continue to smaller sizes
                continue
            }
        }
        catch {
            continue
        }
    }

    if ($result.MaxMTU -eq 0) {
        # Even smallest size failed -- host may block ICMP entirely
        $result.Notes += "All MTU probe sizes failed -- ICMP is likely blocked on this network. MTU test inconclusive (not a middlebox indicator on its own)."
    }
    elseif (-not $result.StandardMTU) {
        $result.ReducedMTU = $true
        $result.PossibleIssue = $true
        $result.Notes += "Path MTU is reduced to ~$($result.MaxMTU) bytes (standard is 1500). This suggests VPN tunnel, NVA, or encapsulation overhead."
    }
    else {
        $result.Notes += "Standard MTU (1500) works -- no encapsulation overhead detected on ICMP path"
    }

    return $result
}

function Test-ConnectionReuse {
    <#
    .SYNOPSIS
        Tests whether repeated requests on the same TLS connection succeed.
        Middleboxes with aggressive idle timers or broken keep-alive handling
        cause failures on reused connections while fresh connections work.
    #>
    param(
        [string]$Url,
        [int]$Requests = 3,
        [int]$DelayBetweenMs = 2000
    )

    $result = [PSCustomObject]@{
        AllSucceeded    = $true
        Results         = @()
        ReuseIssue      = $false
        Notes           = @()
    }

    if ($Url -notmatch '^https?://') { return $result }

    Write-Info "  Testing connection reuse (keep-alive) with $Requests requests..." -Color Gray

    $handler = $null
    $httpClient = $null
    $prevCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($sender, $cert, $chain, $errors) return $true }

    try {
        # Use ServicePointManager for SSL bypass (PS 5.1 / .NET Framework compatible)
        $handler = New-Object System.Net.Http.HttpClientHandler
        $httpClient = New-Object System.Net.Http.HttpClient($handler)
        $httpClient.Timeout = [TimeSpan]::FromSeconds(15)
        [void]$httpClient.DefaultRequestHeaders.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
        $httpClient.DefaultRequestHeaders.ConnectionClose = $false   # keep-alive

        if ($script:SubscriptionKey) {
            [void]$httpClient.DefaultRequestHeaders.Add('ocp-apim-subscription-key', $script:SubscriptionKey)
        }

        for ($i = 1; $i -le $Requests; $i++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $resp = $httpClient.GetAsync($Url).Result
                $sw.Stop()
                $statusCode = [int]$resp.StatusCode
                $result.Results += [PSCustomObject]@{
                    Request    = $i
                    StatusCode = $statusCode
                    LatencyMs  = $sw.ElapsedMilliseconds
                    Success    = ($statusCode -gt 0)
                }
                $resp.Dispose()
            }
            catch {
                $sw.Stop()
                $result.Results += [PSCustomObject]@{
                    Request    = $i
                    StatusCode = 0
                    LatencyMs  = $sw.ElapsedMilliseconds
                    Success    = $false
                    Error      = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
                }
                $result.AllSucceeded = $false
            }

            if ($i -lt $Requests) {
                Start-Sleep -Milliseconds $DelayBetweenMs
            }
        }
    }
    catch {
        $result.Notes += "Connection reuse test error: $($_.Exception.Message)"
    }
    finally {
        if ($httpClient) { $httpClient.Dispose() }
        if ($handler) { $handler.Dispose() }
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCallback
    }

    if ($result.Results.Count -eq 0) { return $result }

    # Analyse results
    $totalFails = ($result.Results | Where-Object { -not $_.Success }).Count
    $firstOk = $result.Results[0].Success

    if ($totalFails -eq $result.Results.Count) {
        $errMsg = if ($result.Results[0].Error) { $result.Results[0].Error } else { 'unknown' }
        $result.Notes += "All $totalFails requests failed (error: $errMsg). This may indicate a proxy, SSL, or connectivity issue -- not necessarily a keep-alive problem."
    } elseif ($firstOk -and $totalFails -gt 0) {
        $result.ReuseIssue = $true
        $result.Notes += "First request succeeded but $totalFails subsequent request(s) failed -- possible middlebox idle-timeout or keep-alive issue"
    }

    if ($result.Results.Count -ge 2 -and $firstOk) {
        $firstLatency = $result.Results[0].LatencyMs
        $laterLatencies = ($result.Results | Select-Object -Skip 1).LatencyMs
        $avgLater = ($laterLatencies | Measure-Object -Average).Average
        if ($avgLater -gt ($firstLatency * 3) -and $avgLater -gt 1000) {
            $result.Notes += "Significant latency increase on connection reuse (first: ${firstLatency}ms, subsequent avg: $([math]::Round($avgLater))ms)"
            $result.ReuseIssue = $true
        }
    }

    return $result
}

function Test-SecurityAgentPresence {
    <#
    .SYNOPSIS
        Detects SASE/SSE/security agents (Netskope, Zscaler, etc.) installed
        on the local machine. These agents can intercept, inspect, or redirect
        traffic even when TLS interception isn't visible for a specific URL
        (e.g., domain-bypass lists can exempt certain sites).
    #>
    param([string]$Hostname)

    $result = [PSCustomObject]@{
        AgentsFound   = @()
        AgentDetected = $false
        Notes         = @()
    }

    # Define known SASE/SSE/proxy security agents
    $agents = @(
        @{
            Name            = 'Netskope'
            Processes       = @('stAgentSvc','STAgent','nssvc','nsservice','NSkpAgent','NSkpClient','nsagentupdater')
            CertPatterns    = @('Netskope','NSkope')
            RegistryPaths   = @('HKLM:\SOFTWARE\Netskope','HKLM:\SOFTWARE\WOW6432Node\Netskope')
            ServicePatterns = @('stAgentSvc','nssvc','NSkpAgent')
            AdapterPatterns = @('Netskope')
        },
        @{
            Name            = 'Zscaler'
            Processes       = @('ZSATunnel','ZscalerService','ZSAService','zscaler')
            CertPatterns    = @('Zscaler','ZscalerRootCertificate')
            RegistryPaths   = @('HKLM:\SOFTWARE\Zscaler','HKLM:\SOFTWARE\WOW6432Node\Zscaler')
            ServicePatterns = @('ZSATunnel','Zscaler')
            AdapterPatterns = @('Zscaler')
        },
        @{
            Name            = 'Palo Alto Prisma / GlobalProtect'
            Processes       = @('PanGPA','PanGPS','GlobalProtect','prisma-access')
            CertPatterns    = @('Palo Alto','GlobalProtect','Prisma Access')
            RegistryPaths   = @('HKLM:\SOFTWARE\Palo Alto Networks')
            ServicePatterns = @('PanGPS','GlobalProtect','PanGPA')
            AdapterPatterns = @('PANGP','GlobalProtect')
        },
        @{
            Name            = 'Cisco Secure Access / Umbrella'
            Processes       = @('csc_ui','swg_agent','Umbrella','acumbrellaagent','vpnagent')
            CertPatterns    = @('Cisco Umbrella','OpenDNS','Cisco Secure')
            RegistryPaths   = @('HKLM:\SOFTWARE\OpenDNS','HKLM:\SOFTWARE\Cisco\Cisco Secure Client')
            ServicePatterns = @('aciseagent','vpnagent','csc_ui','Umbrella')
            AdapterPatterns = @('Cisco AnyConnect','Cisco Secure')
        },
        @{
            Name            = 'Forcepoint ONE / Web Security'
            Processes       = @('FORCEPOINT','fpdiag','FPConnectAgent','fppsvc')
            CertPatterns    = @('Forcepoint')
            RegistryPaths   = @('HKLM:\SOFTWARE\Forcepoint')
            ServicePatterns = @('FPEP','FPConnectAgent','fppsvc')
            AdapterPatterns = @()
        },
        @{
            Name            = 'Symantec / Broadcom WSS'
            Processes       = @('ccSvcHst','WSSSvc')
            CertPatterns    = @('Symantec Web Security','Broadcom Web Security')
            RegistryPaths   = @('HKLM:\SOFTWARE\Symantec\Web Security Service')
            ServicePatterns = @('WSSSvc','SepMasterService')
            AdapterPatterns = @()
        },
        @{
            Name            = 'McAfee / Skyhigh Web Gateway'
            Processes       = @('mwg','McAfeeWG','MFEEsp')
            CertPatterns    = @('McAfee Web Gateway','McAfee MITM','Skyhigh')
            RegistryPaths   = @('HKLM:\SOFTWARE\McAfee\Web Gateway')
            ServicePatterns = @('McAfeeFramework','mfefire')
            AdapterPatterns = @()
        },
        @{
            Name            = 'iboss Cloud Security'
            Processes       = @('iboss','ibsa','ibossDesktopAgent')
            CertPatterns    = @('iboss')
            RegistryPaths   = @('HKLM:\SOFTWARE\iboss')
            ServicePatterns = @('iboss','ibsa')
            AdapterPatterns = @()
        },
        @{
            Name            = 'Menlo Security'
            Processes       = @('menlo','MenloSecurityAgent')
            CertPatterns    = @('Menlo Security')
            RegistryPaths   = @('HKLM:\SOFTWARE\Menlo Security')
            ServicePatterns = @('MenloSecurity')
            AdapterPatterns = @()
        }
    )

    Write-Info "  Scanning for SASE/SSE security agents..." -Color Gray

    foreach ($agent in $agents) {
        $evidence = @()

        # 1. Check running processes
        foreach ($procName in $agent.Processes) {
            try {
                $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
                if ($procs) {
                    $pids = ($procs | ForEach-Object { $_.Id }) -join ', '
                    $evidence += "Process '$procName' is running (PID: $pids)"
                }
            } catch {}
        }

        # 2. Check Windows services
        foreach ($svcPattern in $agent.ServicePatterns) {
            try {
                $svcs = Get-Service -Name "*$svcPattern*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' }
                foreach ($svc in $svcs) {
                    $evidence += "Service '$($svc.Name)' ($($svc.DisplayName)) is running"
                }
            } catch {}
        }

        # 3. Check registry for installation footprint
        foreach ($regPath in $agent.RegistryPaths) {
            try {
                if (Test-Path $regPath) {
                    $evidence += "Registry key present: $regPath"
                }
            } catch {}
        }

        # 4. Check certificate stores for MITM root CAs
        foreach ($certPattern in $agent.CertPatterns) {
            try {
                $escapedPattern = [regex]::Escape($certPattern)
                # Trusted Root CAs
                $rootCerts = Get-ChildItem -Path 'Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Issuer -match $escapedPattern -or $_.Subject -match $escapedPattern }
                foreach ($c in $rootCerts) {
                    $evidence += "Root CA installed: $($c.Subject) (thumbprint: $($c.Thumbprint.Substring(0,8))...)"
                }
                # Intermediate CAs
                $intCerts = Get-ChildItem -Path 'Cert:\LocalMachine\CA' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Issuer -match $escapedPattern -or $_.Subject -match $escapedPattern }
                foreach ($c in $intCerts) {
                    $evidence += "Intermediate CA installed: $($c.Subject)"
                }
            } catch {}
        }

        # 5. Check network adapters
        foreach ($adapterPattern in $agent.AdapterPatterns) {
            try {
                $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
                    Where-Object { $_.InterfaceDescription -match [regex]::Escape($adapterPattern) -or $_.Name -match [regex]::Escape($adapterPattern) }
                foreach ($a in $adapters) {
                    $evidence += "Network adapter: '$($a.Name)' ($($a.InterfaceDescription)) - Status: $($a.Status)"
                }
            } catch {}
        }

        if ($evidence.Count -gt 0) {
            $result.AgentsFound += [PSCustomObject]@{
                Name     = $agent.Name
                Evidence = $evidence
            }
            $result.AgentDetected = $true
        }
    }

    # Summary
    if ($result.AgentDetected) {
        $agentNames = ($result.AgentsFound | ForEach-Object { $_.Name }) -join ', '
        $result.Notes += "Security agent(s) detected on this machine: $agentNames. Even if TLS interception is not visible for '$Hostname', the agent may be steering DNS, tunneling traffic, or bypassing this domain."
    } else {
        $result.Notes += "No SASE/SSE security agents detected on this machine"
    }

    return $result
}

function Test-OriginCertPath {
    <#
    .SYNOPSIS
        Auto-discovers probable origin servers (behind the CDN) and probes them
        directly for TLS cert and IP ownership. If a SASE/SSE device (Netskope,
        Zscaler, etc.) sits between the CDN and origin, this function can detect
        it through:
          - DNS CNAMEs pointing to SASE infrastructure (e.g., *.goskope.com)
          - TLS certificates issued by SASE CAs on the origin
          - IP address ownership by a SASE vendor (ASN/org whois)
    .NOTES
        This test is meaningful because the script user sees the CDN-to-client
        leg (clean), but a middlebox between CDN and origin is invisible unless
        we probe the origin directly.
    #>
    param(
        [string]$Hostname,
        $Response,
        [string[]]$CNAMEChain = @()
    )

    $result = [PSCustomObject]@{
        OriginCandidates = @()     # all discovered origins
        SASEDetected     = $false
        SASEFindings     = @()     # list of [PSCustomObject]@{ Origin; Provider; Evidence; Signal }
        Notes            = @()
    }

    Write-Info "  Discovering origin candidates for $Hostname..." -Color Gray

    # ---- 1. Discover origin candidates ----
    $candidates = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # 1a. Apex domain (strip subdomains down to registrable domain)
    $parts = $Hostname.Split('.')
    if ($parts.Count -ge 2) {
        $apex = "$($parts[-2]).$($parts[-1])"
        # Handle co.uk, com.au, etc. -- crude but effective
        $slds = @('co','com','org','net','edu','gov','ac','gob')
        if ($parts.Count -ge 3 -and $slds -contains $parts[-2]) {
            $apex = "$($parts[-3]).$($parts[-2]).$($parts[-1])"
        }
        if ($apex -ne $Hostname) { [void]$candidates.Add($apex) }
    }

    # 1b. Mine CSP header for whitelisted origins
    if ($Response -and $Response.Headers) {
        $cspHeader = $null
        if ($Response.Headers['Content-Security-Policy']) { $cspHeader = "$($Response.Headers['Content-Security-Policy'])" }
        if ($cspHeader) {
            # Extract https:// URLs from CSP
            $cspMatches = [regex]::Matches($cspHeader, 'https?://([a-zA-Z0-9\-\.]+)')
            foreach ($m in $cspMatches) {
                $cspHost = $m.Groups[1].Value.TrimEnd('.')
                # Skip known public CDNs, google, and the hostname itself
                if ($cspHost -ne $Hostname -and
                    $cspHost -notmatch '(googleapis|gstatic|google|cloudflare|cdnjs|jsdelivr|unpkg|jquery|bootstrapcdn)') {
                    [void]$candidates.Add($cspHost)
                }
            }
        }

        # 1c. Mine CORS Access-Control-Allow-Origin
        $corsHeader = $null
        if ($Response.Headers['Access-Control-Allow-Origin']) { $corsHeader = "$($Response.Headers['Access-Control-Allow-Origin'])" }
        if ($corsHeader -and $corsHeader -ne '*') {
            $corsMatch = [regex]::Match($corsHeader, 'https?://([a-zA-Z0-9\-\.]+)')
            if ($corsMatch.Success) {
                $corsHost = $corsMatch.Groups[1].Value.TrimEnd('.')
                if ($corsHost -ne $Hostname) { [void]$candidates.Add($corsHost) }
            }
        }

        # 1d. Check X-Powered-By / Server for platform hints -> construct origin guess
        $poweredBy = $null
        if ($Response.Headers['X-Powered-By']) { $poweredBy = "$($Response.Headers['X-Powered-By'])" }
        if ($poweredBy -match 'ASP\.NET|Express|PHP') {
            # Try common Azure App Service naming: {sitename}.azurewebsites.net
            $baseName = ($Hostname -replace '\..*$', '')
            [void]$candidates.Add("$baseName.azurewebsites.net")
        }
    }

    # 1e. Common origin naming patterns
    $baseName = ($Hostname -replace '\..*$', '')
    $domainSuffix = $Hostname.Substring($baseName.Length + 1)
    $originGuesses = @(
        "origin.$Hostname",
        "origin-$Hostname",
        "origin.$domainSuffix",
        "api.$domainSuffix",
        "backend.$domainSuffix",
        "app.$domainSuffix"
    )
    foreach ($guess in $originGuesses) {
        [void]$candidates.Add($guess)
    }

    # 1f. Check CNAME chain for non-CDN entries that might be origin
    foreach ($cname in $CNAMEChain) {
        # Skip known CDN CNAMEs
        if ($cname -match 'azurefd\.net|afdverify|trafficmanager|msedge\.net|cloudfront|fastly|akamai|edgecast|cloudflare') { continue }
        [void]$candidates.Add($cname)
    }

    # Remove the original hostname and any CDN hostnames
    [void]$candidates.Remove($Hostname)

    $result.OriginCandidates = @($candidates)
    if ($candidates.Count -eq 0) {
        $result.Notes += "No origin candidates discovered"
        return $result
    }

    Write-Info "  Found $($candidates.Count) origin candidate(s): $($candidates -join ', ')" -Color Gray

    # ---- 2. Check DNS of each candidate for SASE CNAME patterns ----
    Write-Info "  Probing origin candidates for SASE/middlebox indicators..." -Color Gray

    foreach ($origin in $candidates) {
        # 2a. DNS resolution -- look for SASE CNAMEs
        $dnsChain = @()
        try {
            $dnsRecords = Resolve-DnsName -Name $origin -ErrorAction SilentlyContinue
            if (-not $dnsRecords) { continue }  # NXDOMAIN or no result

            foreach ($rec in $dnsRecords) {
                if ($rec.Type -eq 'CNAME') {
                    $dnsChain += $rec.NameHost
                }
            }
            $resolvedIPs = @($dnsRecords | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress })
        }
        catch { continue }  # skip unresolvable candidates

        # Check CNAME chain for SASE patterns
        $allDnsText = ($dnsChain + @($origin)) -join ' '
        foreach ($saseProvider in $script:SASEDnsPatterns) {
            foreach ($pattern in $saseProvider.Patterns) {
                if ($allDnsText -match [regex]::Escape($pattern)) {
                    $result.SASEDetected = $true
                    $result.SASEFindings += [PSCustomObject]@{
                        Origin   = $origin
                        Provider = $saseProvider.Name
                        Evidence = "DNS CNAME chain contains '$pattern': $($dnsChain -join ' -> ')"
                        Signal   = 'HIGH'
                    }
                    Write-Info "    [!] SASE DNS match: $origin -> $($saseProvider.Name) ($pattern)" -Color Red
                }
            }
        }

        # 2b. TLS certificate probe (connect directly on 443)
        if ($resolvedIPs.Count -gt 0) {
            $tcpClient = $null
            $sslStream = $null
            try {
                $tcpClient = [System.Net.Sockets.TcpClient]::new()
                $connectTask = $tcpClient.ConnectAsync($origin, 443)
                if (-not $connectTask.Wait(5000)) {
                    throw "TLS connect to $origin timed out after 5 seconds"
                }

                $validationCallback = [Net.Security.RemoteCertificateValidationCallback]{ param($s,$c,$ch,$e); return $true }
                $sslStream = [Net.Security.SslStream]::new($tcpClient.GetStream(), $false, $validationCallback)
                $sslStream.ReadTimeout = 5000
                $sslStream.AuthenticateAsClient($origin)

                $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($sslStream.RemoteCertificate)
                $issuerText = "$($cert.Issuer) $($cert.GetNameInfo('SimpleName',$true))"

                $matchedHigh = $false
                foreach ($pattern in $script:HighConfidenceMITMIssuers) {
                    if ($issuerText -match [regex]::Escape($pattern)) {
                        $result.SASEDetected = $true
                        $result.SASEFindings += [PSCustomObject]@{
                            Origin   = $origin
                            Provider = $pattern
                            Evidence = "TLS cert issuer matches SASE/MITM pattern '$pattern': $($cert.Issuer)"
                            Signal   = 'HIGH'
                        }
                        Write-Info "    [!] SASE TLS cert: $origin issuer matches '$pattern'" -Color Red
                        $matchedHigh = $true
                        break
                    }
                }

                if (-not $matchedHigh) {
                    foreach ($pattern in $script:WeakMITMIssuers) {
                        if ($issuerText -match [regex]::Escape($pattern)) {
                            $result.SASEDetected = $true
                            $result.SASEFindings += [PSCustomObject]@{
                                Origin   = $origin
                                Provider = $pattern
                                Evidence = "TLS cert issuer contains weak MITM marker '$pattern': $($cert.Issuer)"
                                Signal   = 'MEDIUM'
                            }
                            Write-Info "    [!] Possible SASE TLS cert: $origin issuer contains '$pattern'" -Color Yellow
                            break
                        }
                    }
                }

                # Also record the cert for display even if clean
                $result.Notes += "Origin '$origin' TLS cert: Subject=$($cert.Subject), Issuer=$($cert.Issuer)"
            }
            catch {
                # Connection refused or timeout is fine -- origin may not be directly reachable
                $result.Notes += "Origin '$origin' port 443 not reachable directly: $($_.Exception.Message -replace '[\r\n]+',' ')"
            }
            finally {
                if ($sslStream) { $sslStream.Dispose() }
                if ($tcpClient) { $tcpClient.Close(); $tcpClient.Dispose() }
            }
        }

        # 2c. IP ownership check via ip-api.com (rate-limit friendly: max 3 IPs)
        $ipsToCheck = @($resolvedIPs | Select-Object -First 3)
        foreach ($ip in $ipsToCheck) {
            try {
                $geo = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip" -TimeoutSec 5 -ErrorAction SilentlyContinue
                if ($geo -and $geo.status -eq 'success') {
                    $orgText = "$($geo.org) $($geo.isp) $($geo.as)"
                    foreach ($saseOrg in $script:SASEIPOrgPatterns) {
                        foreach ($orgPattern in $saseOrg.Patterns) {
                            if ($orgText -match [regex]::Escape($orgPattern)) {
                                $result.SASEDetected = $true
                                $result.SASEFindings += [PSCustomObject]@{
                                    Origin   = $origin
                                    Provider = $saseOrg.Name
                                    Evidence = "Origin IP $ip belongs to $($saseOrg.Name) (Org: $($geo.org), ISP: $($geo.isp), AS: $($geo.as))"
                                    Signal   = 'HIGH'
                                }
                                Write-Info "    [!] SASE IP: $ip belongs to $($saseOrg.Name)" -Color Red
                            }
                        }
                    }
                }
                Start-Sleep -Milliseconds 200   # rate-limit courtesy
            }
            catch { }
        }
    }

    if (-not $result.SASEDetected) {
        $result.Notes += "No SASE/SSE middlebox indicators found on origin candidates"
    }

    return $result
}

function Test-MiddlemanPresence {
    <#
    .SYNOPSIS
        Orchestrates all middleman / middlebox detection checks for a given URL.
        Returns a comprehensive result object with findings from every method.
    #>
    param(
        [string]$Url,
        $Response,
        $TLSInfo,
        [string[]]$CNAMEChain = @()
    )

    $uri = [Uri]$Url
    $hostname = $uri.Host

    Write-Info "`n--- Middleman / Middlebox Detection ---" -Color Magenta
    Write-Info "Running middlebox detection checks for $hostname..." -Color Gray

    # 1. TLS Interception Check
    Write-Info "  [1/8] Checking TLS certificate for interception..." -Color Gray
    $tlsInterception = Test-TLSInterception -Url $Url

    # 2. DNS steering comparison
    Write-Info "  [2/8] Checking for DNS steering (system vs public resolver)..." -Color Gray
    $dnsSteering = Test-DnsSteering -Hostname $hostname

    # 3. Proxy Header Analysis
    Write-Info "  [3/8] Analyzing response headers for proxy indicators..." -Color Gray
    $proxyHeaders = $null
    if ($Response) {
        $proxyHeaders = Test-ProxyHeaders -Headers $Response.Headers
    } else {
        $proxyHeaders = [PSCustomObject]@{
            ProxyDetected = $false
            DetectedHeaders = @()
            Notes = @('No HTTP response available for header analysis')
            HighConfidenceHeaders = @()
            WeakHeaders = @()
        }
    }

    # 4. System Proxy Configuration
    Write-Info "  [4/8] Checking system proxy configuration..." -Color Gray
    $proxyConfig = Get-SystemProxyConfiguration

    # 5. Security Agent Detection (Netskope, Zscaler, etc.)
    Write-Info "  [5/8] Scanning for SASE/SSE security agents..." -Color Gray
    $securityAgents = Test-SecurityAgentPresence -Hostname $hostname

    # 6. Origin Cert / SASE Path Detection
    Write-Info "  [6/8] Probing origin servers for SASE/middlebox in CDN-to-origin path..." -Color Gray
    $originCertPath = Test-OriginCertPath -Hostname $hostname -Response $Response -CNAMEChain $CNAMEChain

    # 7. Traceroute Analysis
    Write-Info "  [7/8] Running traceroute analysis..." -Color Gray
    $traceroute = Get-TracerouteAnalysis -Hostname $hostname

    # 8. MTU Path Discovery
    Write-Info "  [8/8] Testing path MTU..." -Color Gray
    $mtuTest = Test-MTUPathDiscovery -Hostname $hostname

    # 8. Connection Reuse Test (bonus -- fast)
    Write-Info "  [bonus] Testing connection reuse (keep-alive)..." -Color Gray
    $connReuse = Test-ConnectionReuse -Url $Url

    # Build overall verdict
    $signals = [System.Collections.Generic.List[object]]::new()
    $confidence = 'None'
    $middlemanDetected = $false
    $addSignal = {
        param($check,$signal,$detail)
        $signals.Add([PSCustomObject]@{ Check = $check; Signal = $signal; Detail = $detail })
        if ($signal -ne 'INFO') {
            Set-Variable -Name middlemanDetected -Scope 1 -Value $true
        }
    }

    if ($tlsInterception.HighConfidenceMatches.Count -gt 0 -or $tlsInterception.Intercepted) {
        $detail = if ($tlsInterception.Notes.Count -gt 0) { $tlsInterception.Notes -join '; ' } else { "Issuer: $($tlsInterception.Issuer)" }
        & $addSignal 'TLS Interception' 'HIGH' $detail
    } elseif ($tlsInterception.WeakMatches.Count -gt 0) {
        $detail = if ($tlsInterception.Notes.Count -gt 0) { $tlsInterception.Notes -join '; ' } else { 'Weak TLS indicators present' }
        & $addSignal 'TLS Inspection Hints' 'LOW' $detail
    }

    if ($dnsSteering.DivergenceDetected) {
        $detail = if ($dnsSteering.Notes.Count -gt 0) { $dnsSteering.Notes[-1] } else { 'System and public DNS returned different answers' }
        & $addSignal 'DNS Steering' 'HIGH' $detail
    }

    if ($proxyHeaders.ProxyDetected) {
        $detail = if ($proxyHeaders.Notes.Count -gt 0) { $proxyHeaders.Notes -join '; ' } else { 'Proxy headers observed' }
        if ($proxyHeaders.HighConfidenceHeaders.Count -gt 0) {
            & $addSignal 'Proxy Authentication Header' 'HIGH' "$detail (Headers: $($proxyHeaders.HighConfidenceHeaders -join ', '))"
        } else {
            & $addSignal 'Proxy Headers' 'LOW' $detail
        }
    }

    if ($proxyConfig.ProxyConfigured) {
        $detail = if ($proxyConfig.Notes.Count -gt 0) { $proxyConfig.Notes -join '; ' } else { 'System proxy configured' }
        & $addSignal 'System Proxy Config' 'HIGH' $detail
    }

    if ($securityAgents.AgentDetected) {
        foreach ($agentInfo in $securityAgents.AgentsFound) {
            $evidenceSummary = ($agentInfo.Evidence | Select-Object -First 3) -join '; '
            if ($agentInfo.Evidence.Count -gt 3) { $evidenceSummary += " (+$($agentInfo.Evidence.Count - 3) more)" }
            & $addSignal "Security Agent ($($agentInfo.Name))" 'HIGH' $evidenceSummary
        }
    }

    if ($originCertPath.SASEDetected) {
        foreach ($finding in $originCertPath.SASEFindings) {
            & $addSignal "Origin SASE/SSE ($($finding.Provider))" $finding.Signal $finding.Evidence
        }
    }

    if ($traceroute.SuspiciousHops.Count -gt 0) {
        $hopDetails = ($traceroute.SuspiciousHops | ForEach-Object { "Hop $($_.Hop) ($($_.IP)): $($_.Reason)" }) -join '; '
        & $addSignal 'Traceroute' 'MEDIUM' $hopDetails
    }

    if ($traceroute.Notes.Count -gt 0) {
        $tcpSucceeded = $traceroute.TCPTest -and $traceroute.TCPTest.TcpTestSucceeded
        foreach ($note in $traceroute.Notes) {
            if ($note -match 'consecutive timeout|ICMP-suppress' -and $note -notmatch 'All .+ hops timed out|inconclusive|aborted after') {
                if ($tcpSucceeded -and $note -match 'at end of path') {
                    continue
                }
                & $addSignal 'Traceroute (ICMP suppression)' 'LOW' $note
            }
        }
    }

    if ($traceroute.TCPTest -and $traceroute.TCPTest.IsVPN) {
        $detail = "Traffic is routed through VPN interface '$($traceroute.TCPTest.InterfaceAlias)'. VPN gateways can modify packets, re-encrypt TLS, inject headers, or enforce content policies."
        & $addSignal 'VPN Interface' 'MEDIUM' $detail
    }

    if ($mtuTest.PossibleIssue) {
        $detail = if ($mtuTest.Notes.Count -gt 0) { $mtuTest.Notes -join '; ' } else { 'Reduced MTU detected' }
        & $addSignal 'MTU Path Discovery' 'MEDIUM' $detail
    }

    if ($connReuse.ReuseIssue) {
        $detail = if ($connReuse.Notes.Count -gt 0) { $connReuse.Notes -join '; ' } else { 'Connection reuse failed' }
        & $addSignal 'Connection Reuse' 'MEDIUM' $detail
    }

    # Determine overall confidence
    $highSignals  = ($signals | Where-Object { $_.Signal -eq 'HIGH' }).Count
    $medSignals   = ($signals | Where-Object { $_.Signal -eq 'MEDIUM' }).Count
    $lowSignals   = ($signals | Where-Object { $_.Signal -eq 'LOW' }).Count
    if ($highSignals -ge 1) {
        $confidence = 'HIGH'
    } elseif ($medSignals -ge 2) {
        $confidence = 'HIGH'
    } elseif ($medSignals -eq 1) {
        $confidence = 'MEDIUM'
    } elseif ($lowSignals -gt 0) {
        $confidence = 'LOW'
    }

    return [PSCustomObject]@{
        MiddlemanDetected  = $middlemanDetected
        Confidence         = $confidence
        Signals            = $signals
        TLSInterception    = $tlsInterception
        DnsSteering        = $dnsSteering
        ProxyHeaders       = $proxyHeaders
        ProxyConfig        = $proxyConfig
        SecurityAgents     = $securityAgents
        OriginCertPath     = $originCertPath
        Traceroute         = $traceroute
        MTUTest            = $mtuTest
        ConnectionReuse    = $connReuse
    }
}

function Show-MiddlemanResults {
    <#
    .SYNOPSIS
        Displays the middleman detection results in a formatted output.
    #>
    param([PSCustomObject]$MiddlemanInfo)

    if (-not $MiddlemanInfo) { return }

    # --- Overall Verdict ---
    Write-Info "`n=== MIDDLEMAN / MIDDLEBOX DETECTION RESULTS ===" -Color Magenta
    if ($MiddlemanInfo.MiddlemanDetected) {
        $color = switch ($MiddlemanInfo.Confidence) {
            'HIGH'   { 'Red' }
            'MEDIUM' { 'Yellow' }
            default  { 'Gray' }
        }
        Write-Info "  MIDDLEBOX DETECTED  (Confidence: $($MiddlemanInfo.Confidence))" -Color $color
    } else {
        Write-Info "  No middlebox indicators found" -Color Green
    }

    # --- Signal Summary ---
    if ($MiddlemanInfo.Signals.Count -gt 0) {
        Write-Info "`n  Detection Signals:" -Color Cyan
        foreach ($sig in $MiddlemanInfo.Signals) {
            $sigColor = switch ($sig.Signal) {
                'HIGH'   { 'Red' }
                'MEDIUM' { 'Yellow' }
                default  { 'Gray' }
            }
            Write-Info "    [$($sig.Signal)] $($sig.Check)" -Color $sigColor
            Write-Info "        $($sig.Detail)" -Color Gray
        }
    }

    # --- TLS Interception Detail ---
    Write-Info "`n  1. TLS Certificate Inspection:" -Color Cyan
    if ($MiddlemanInfo.TLSInterception.Intercepted) {
        Write-Info "     INTERCEPTED - Certificate chain is NOT from a well-known public CA" -Color Red
        Write-Info "     Issuer: $($MiddlemanInfo.TLSInterception.Issuer)" -Color Yellow
        if ($MiddlemanInfo.TLSInterception.MatchedPattern) {
            Write-Info "     Matched: $($MiddlemanInfo.TLSInterception.MatchedPattern)" -Color Yellow
        }
    } else {
        Write-Info "     Certificate chain appears legitimate (no TLS interception detected)" -Color Green
        if ($MiddlemanInfo.TLSInterception.Issuer) {
            Write-Info "     Issuer: $($MiddlemanInfo.TLSInterception.Issuer)" -Color Gray
        }
    }
    if ($MiddlemanInfo.TLSInterception.LeafThumbprint) {
        Write-Info "     Leaf Thumbprint: $($MiddlemanInfo.TLSInterception.LeafThumbprint)" -Color Gray
    }
    if ($MiddlemanInfo.TLSInterception.SubjectAlternativeNames.Count -gt 0) {
        $sanDisplay = ($MiddlemanInfo.TLSInterception.SubjectAlternativeNames | Select-Object -First 5) -join ', '
        if ($MiddlemanInfo.TLSInterception.SubjectAlternativeNames.Count -gt 5) {
            $sanDisplay += ' ...'
        }
        Write-Info "     SANs: $sanDisplay" -Color Gray
    }
    if ($MiddlemanInfo.TLSInterception.HostnameMatches -eq $false) {
        Write-Info "     [!] Hostname does NOT match certificate SAN/CN" -Color Yellow
    }
    if ($MiddlemanInfo.TLSInterception.SslPolicyErrors -and $MiddlemanInfo.TLSInterception.SslPolicyErrors -ne 'None') {
        Write-Info "     SSL Policy Errors: $($MiddlemanInfo.TLSInterception.SslPolicyErrors)" -Color Yellow
    }
    if ($MiddlemanInfo.TLSInterception.CertificateChain.Count -gt 0) {
        Write-Info "     Certificate Chain:" -Color Gray
        foreach ($chainCert in $MiddlemanInfo.TLSInterception.CertificateChain) {
            Write-Info "       -> $($chainCert.Subject)" -Color Gray
        }
    }
    foreach ($note in $MiddlemanInfo.TLSInterception.Notes) {
        Write-Info "     Note: $note" -Color Gray
    }

    # --- DNS Steering ---
    Write-Info "`n  2. DNS Steering Check:" -Color Cyan
    $dns = $MiddlemanInfo.DnsSteering
    if ($dns) {
        if ($dns.DivergenceDetected) {
            Write-Info "     DNS ANSWERS DIFFER between system and public resolver" -Color Red
        } elseif (-not ($dns.SystemQuerySucceeded -and $dns.PublicQuerySucceeded)) {
            Write-Info "     DNS comparison inconclusive" -Color Yellow
        } else {
            Write-Info "     System and public DNS returned the same answers" -Color Green
        }
        if ($dns.SystemAddresses.Count -gt 0) {
            $systemResolverLabel = if ($dns.SystemResolver) { $dns.SystemResolver } else { 'default' }
            Write-Info "     System Resolver ($systemResolverLabel) -> $($dns.SystemAddresses -join ', ')" -Color Gray
        }
        if ($dns.PublicAddresses.Count -gt 0) {
            Write-Info "     Public Resolver ($($dns.PublicResolver)) -> $($dns.PublicAddresses -join ', ')" -Color Gray
        }
        foreach ($note in $dns.Notes) {
            Write-Info "     Note: $note" -Color Gray
        }
    } else {
        Write-Info "     DNS steering test unavailable" -Color Gray
    }

    # --- Proxy Headers ---
    Write-Info "`n  3. Proxy Header Analysis:" -Color Cyan
    if ($MiddlemanInfo.ProxyHeaders.ProxyDetected) {
        Write-Info "     Proxy-indicating headers FOUND in response" -Color Yellow
        foreach ($ph in $MiddlemanInfo.ProxyHeaders.DetectedHeaders) {
            Write-Info "     $($ph.Header): $($ph.Value)" -Color Yellow
        }
    } else {
        Write-Info "     No proxy-indicating headers detected" -Color Green
    }
    foreach ($note in $MiddlemanInfo.ProxyHeaders.Notes) {
        Write-Info "     Note: $note" -Color Gray
    }

    # --- System Proxy Config ---
    Write-Info "`n  4. System Proxy Configuration:" -Color Cyan
    if ($MiddlemanInfo.ProxyConfig.ProxyConfigured) {
        Write-Info "     System-level proxy IS configured" -Color Yellow
        if ($MiddlemanInfo.ProxyConfig.WinINetProxy) {
            Write-Info "     WinINet Proxy: $($MiddlemanInfo.ProxyConfig.WinINetProxy)" -Color Yellow
        }
        if ($MiddlemanInfo.ProxyConfig.PACUrl) {
            Write-Info "     PAC URL: $($MiddlemanInfo.ProxyConfig.PACUrl)" -Color Yellow
        }
        if ($MiddlemanInfo.ProxyConfig.WPADEnabled) {
            Write-Info "     WPAD: Active (auto-proxy discovery enabled)" -Color Yellow
        }
        if ($MiddlemanInfo.ProxyConfig.EnvProxies.Count -gt 0) {
            foreach ($ep in $MiddlemanInfo.ProxyConfig.EnvProxies) {
                Write-Info "     ENV: $($ep.Variable) = $($ep.Value)" -Color Yellow
            }
        }
    } else {
        Write-Info "     No system-level proxy configuration detected" -Color Green
    }
    foreach ($note in $MiddlemanInfo.ProxyConfig.Notes) {
        Write-Info "     Note: $note" -Color Gray
    }

    # --- Security Agent Detection ---
    Write-Info "`n  5. Security Agent Detection (SASE/SSE):" -Color Cyan
    if ($MiddlemanInfo.SecurityAgents.AgentDetected) {
        foreach ($agentInfo in $MiddlemanInfo.SecurityAgents.AgentsFound) {
            Write-Info "     DETECTED: $($agentInfo.Name)" -Color Red
            foreach ($ev in $agentInfo.Evidence) {
                Write-Info "       - $ev" -Color Yellow
            }
        }
        Write-Info "     [!] A security agent on this machine can intercept, re-encrypt, or redirect" -Color Yellow
        Write-Info "         traffic for ANY domain, even if TLS interception was not detected above." -Color Yellow
        Write-Info "         The agent may have a domain bypass list that exempts this specific site." -Color Yellow
    } else {
        Write-Info "     No SASE/SSE security agents detected on this machine" -Color Green
    }

    # --- Origin Cert / SASE Path Detection ---
    Write-Info "`n  6. Origin SASE/Middlebox Probe (CDN-to-Origin Path):" -Color Cyan
    if ($MiddlemanInfo.OriginCertPath) {
        $ocp = $MiddlemanInfo.OriginCertPath
        if ($ocp.OriginCandidates.Count -gt 0) {
            Write-Info "     Origin candidates discovered: $($ocp.OriginCandidates -join ', ')" -Color Gray
        }
        if ($ocp.SASEDetected) {
            foreach ($finding in $ocp.SASEFindings) {
                Write-Info "     SASE/SSE DETECTED on origin path:" -Color Red
                Write-Info "       Provider: $($finding.Provider)" -Color Red
                Write-Info "       Origin:   $($finding.Origin)" -Color Yellow
                Write-Info "       Evidence: $($finding.Evidence)" -Color Yellow
            }
            Write-Info "     [!] A security service is intercepting traffic between the CDN and origin." -Color Yellow
            Write-Info "         This can cause TLS errors, latency, or content modification even though" -Color Yellow
            Write-Info "         the client-to-CDN connection appears clean." -Color Yellow
        } else {
            Write-Info "     No SASE/SSE middlebox indicators found on discovered origin candidates" -Color Green
        }
        foreach ($note in $ocp.Notes) {
            Write-Info "     Note: $note" -Color Gray
        }
    } else {
        Write-Info "     Origin probe not available" -Color Gray
    }

    # --- Traceroute ---
    Write-Info "`n  7. Traceroute / Path Analysis:" -Color Cyan

    # 4a. TCP connectivity test (always most reliable for CDN endpoints)
    if ($MiddlemanInfo.Traceroute.TCPTest) {
        $tcp = $MiddlemanInfo.Traceroute.TCPTest
        $tcpColor = if ($tcp.TcpTestSucceeded) { 'Green' } else { 'Red' }
        $ifColor = if ($tcp.IsVPN) { 'Yellow' } else { 'Gray' }
        Write-Info "     TCP Connectivity Test (port $($tcp.RemotePort)):" -Color Cyan
        Write-Info "       Result:    $(if ($tcp.TcpTestSucceeded) { 'SUCCEEDED' } else { 'FAILED' })" -Color $tcpColor
        Write-Info "       Remote:    $($tcp.RemoteAddress)" -Color Gray
        Write-Info "       Source:    $($tcp.SourceAddress)" -Color Gray
        Write-Info "       Interface: $($tcp.InterfaceAlias)$(if ($tcp.IsVPN) { '  ** VPN DETECTED **' } else { '' })" -Color $ifColor
        Write-Info "       Next Hop:  $($tcp.NextHop)" -Color Gray
        if ($tcp.ResolvedAddresses.Count -gt 1) {
            Write-Info "       All IPs:   $($tcp.ResolvedAddresses -join ', ')" -Color Gray
        }
        if ($tcp.IsVPN) {
            Write-Info "       [!] Traffic is flowing through a VPN tunnel. The VPN gateway is an on-path" -Color Yellow
            Write-Info "           middlebox that may inspect, re-encrypt, or modify traffic." -Color Yellow
        }
    }

    # 4b. ICMP traceroute results (may be incomplete/aborted)
    if ($MiddlemanInfo.Traceroute.ICMPAborted) {
        Write-Info "`n     ICMP Traceroute: Aborted (ICMP blocked -- common for CDN/AFD endpoints)" -Color Yellow
        if ($MiddlemanInfo.Traceroute.Hops.Count -gt 0) {
            Write-Info "     Partial hops before abort ($($MiddlemanInfo.Traceroute.Hops.Count) captured):" -Color Gray
            foreach ($hop in $MiddlemanInfo.Traceroute.Hops) {
                $latencyStr = if ($hop.AvgLatency -ge 0) { "$($hop.AvgLatency) ms" } else { "* * *" }
                $hopColor = if ($hop.Suspicious) { 'Yellow' } elseif ($hop.Timeouts -eq 3) { 'Gray' } else { 'White' }
                Write-Info ("       {0,-4} {1,-18} {2}" -f $hop.Hop, $hop.IP, $latencyStr) -Color $hopColor
            }
        }
    } else {
        Write-Info "`n     ICMP Traceroute:" -Color Cyan
        Write-Info "     Total hops: $($MiddlemanInfo.Traceroute.TotalHops), Timeout hops: $($MiddlemanInfo.Traceroute.TimeoutHops)" -Color Gray
        if ($MiddlemanInfo.Traceroute.Hops.Count -gt 0) {
            Write-Info "     Hop  IP                 Hostname                         Latency    Status" -Color Gray
            Write-Info "     ---  --                 --------                         -------    ------" -Color Gray
            foreach ($hop in $MiddlemanInfo.Traceroute.Hops) {
                $latencyStr = if ($hop.AvgLatency -ge 0) { "$($hop.AvgLatency) ms" } else { "* * *" }
                $statusStr = if ($hop.Suspicious) { "SUSPICIOUS" } elseif ($hop.Timeouts -eq 3) { "timeout" } else { "ok" }
                $hopColor = if ($hop.Suspicious) { 'Yellow' } elseif ($hop.Timeouts -eq 3) { 'Gray' } else { 'White' }
                $ipPad = $hop.IP.PadRight(18)
                $namePad = if ($hop.HostName) { $hop.HostName.PadRight(32) } else { ''.PadRight(32) }
                Write-Info ("     {0,-4} {1} {2} {3,-10} {4}" -f $hop.Hop, $ipPad, $namePad, $latencyStr, $statusStr) -Color $hopColor
            }
        }
    }
    if ($MiddlemanInfo.Traceroute.SuspiciousHops.Count -gt 0) {
        Write-Info "`n     Suspicious hops:" -Color Yellow
        foreach ($sh in $MiddlemanInfo.Traceroute.SuspiciousHops) {
            Write-Info "       Hop $($sh.Hop) ($($sh.IP)) -- $($sh.Reason)" -Color Yellow
        }
    }
    foreach ($note in $MiddlemanInfo.Traceroute.Notes) {
        Write-Info "     Note: $note" -Color Gray
    }

    # --- MTU ---
    Write-Info "`n  8. MTU Path Discovery:" -Color Cyan
    if ($MiddlemanInfo.MTUTest.PossibleIssue) {
        Write-Info "     REDUCED MTU detected: ~$($MiddlemanInfo.MTUTest.MaxMTU) bytes (standard: 1500)" -Color Yellow
        Write-Info "     This typically indicates VPN tunneling, NVA encapsulation, or MPLS overhead" -Color Yellow
    } elseif ($MiddlemanInfo.MTUTest.StandardMTU) {
        Write-Info "     Standard MTU (1500 bytes) -- no encapsulation overhead detected" -Color Green
    } else {
        foreach ($note in $MiddlemanInfo.MTUTest.Notes) {
            Write-Info "     $note" -Color Gray
        }
    }

    # --- Connection Reuse ---
    Write-Info "`n  9. Connection Reuse (Keep-Alive) Test:" -Color Cyan
    # Guard against accidental array wrapping from pipeline output
    $reuseObj = $MiddlemanInfo.ConnectionReuse
    if ($reuseObj -is [array]) { $reuseObj = $reuseObj[-1] }
    if ($reuseObj.Results.Count -gt 0) {
        foreach ($cr in $reuseObj.Results) {
            $crColor = if ($cr.Success) { 'Green' } else { 'Red' }
            $crStatus = if ($cr.Success) { "OK ($($cr.StatusCode))" } else { "FAIL ($($cr.StatusCode))" }
            $errInfo = if ($cr.Error) { "  [$($cr.Error)]" } else { '' }
            Write-Info "     Request $($cr.Request): $crStatus  ($($cr.LatencyMs) ms)$errInfo" -Color $crColor
        }
    }
    if ($reuseObj.ReuseIssue) {
        Write-Info "     CONNECTION REUSE ISSUE DETECTED" -Color Yellow
        foreach ($note in $reuseObj.Notes) {
            Write-Info "     $note" -Color Yellow
        }
    } elseif (-not $reuseObj.AllSucceeded -and $reuseObj.Results.Count -gt 0) {
        Write-Info "     Some or all requests failed -- see notes above" -Color Yellow
        foreach ($note in $reuseObj.Notes) {
            Write-Info "     $note" -Color Yellow
        }
    } else {
        Write-Info "     Connection reuse appears healthy" -Color Green
    }
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
    
    # Middleman / Middlebox Detection (main URL only)
    $middlemanInfo = $null
    if ($IsMainUrl) {
        Write-Verbose "Running middleman detection checks..."
        $middlemanInfo = Test-MiddlemanPresence -Url $Url -Response $response -TLSInfo $tlsInfo -CNAMEChain $domainInfo.CNAMEChain
        Write-Verbose "Middleman detection completed"
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
        MiddlemanInfo = $middlemanInfo
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
                Write-Info "  * $cause"
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
            Write-Info "[!] WARNING: This response appears to be a WAF challenge page, not the actual site content" -Color Yellow
            Write-Info "WAF Provider: $wafProvider" -Color Yellow
            if ($wafIndicators.Count -gt 0) {
                Write-Info "Indicators:" -Color Gray
                foreach ($indicator in $wafIndicators) {
                    Write-Info "  * $indicator" -Color Gray
                }
            }
            Write-Info "`nNote: Security headers and content analysis below may be incomplete." -Color Yellow
            Write-Info "The actual site likely has additional security headers after passing the challenge." -Color Gray
            Write-Info "To see real headers, use a browser with DevTools (F12 -> Network tab)." -Color Gray
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
                Write-Info "  [+] $($h.Name)" -Color Green
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
                Write-Info "  [-] $($h.Name) [$($h.Severity)] - $($h.Description)" -Color $color
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
    
    # Middleman / Middlebox Detection Results
    if ($Analysis.MiddlemanInfo) {
        Show-MiddlemanResults -MiddlemanInfo $Analysis.MiddlemanInfo
    }
}

# Main execution
try {
    # Validate URL parameter
    if (-not $Url) {
        Write-Err "URL parameter is required. Usage: .\CheckCDNInfov2.ps1 -Url 'https://example.com'"
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
    
    # Final Middleman / Middlebox Summary
    if ($mainAnalysis.MiddlemanInfo) {
        Write-Info "`n=== FINAL MIDDLEMAN / MIDDLEBOX SUMMARY ===" -Color Magenta
        if ($mainAnalysis.MiddlemanInfo.MiddlemanDetected) {
            $mmColor = switch ($mainAnalysis.MiddlemanInfo.Confidence) {
                'HIGH'   { 'Red' }
                'MEDIUM' { 'Yellow' }
                default  { 'Gray' }
            }
            Write-Info "  MIDDLEBOX PRESENCE: DETECTED (Confidence: $($mainAnalysis.MiddlemanInfo.Confidence))" -Color $mmColor
            Write-Info "  Signals found: $($mainAnalysis.MiddlemanInfo.Signals.Count)" -Color $mmColor
            foreach ($sig in $mainAnalysis.MiddlemanInfo.Signals) {
                $sigColor = switch ($sig.Signal) {
                    'HIGH'   { 'Red' }
                    'MEDIUM' { 'Yellow' }
                    default  { 'Gray' }
                }
                Write-Info "    [$($sig.Signal)] $($sig.Check): $($sig.Detail)" -Color $sigColor
            }
            Write-Info "" -Color White
            Write-Info "  RECOMMENDATION: Compare results from corporate network vs. LTE/hotspot." -Color Cyan
            Write-Info "  If issues only occur on corporate network, an on-path enterprise device" -Color Cyan
            Write-Info "  (NVA, firewall, TLS inspection proxy) is almost certainly involved." -Color Cyan
        } else {
            Write-Info "  No middlebox indicators detected on this network path" -Color Green
        }
    }
    
    Write-Info "`nAnalysis completed successfully!" -Color Green
}
catch {
    Write-Err "Fatal error during analysis" $_.Exception.Message
    exit 1
}
