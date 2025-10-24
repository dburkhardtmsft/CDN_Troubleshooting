These are local CDN Troubleshooting PowerShell Scripts, and here is the background info what they do:

**CheckCDNInfo_v1025** = Obtain HTTP Header Info, HTTP Status Code, DNS, Azure Ref Codes, Other CDNs Using, Origin Info, Compression, Cert Status
 
**CDN_PerfDiag_v1025** = Troubleshooting latency or reliability issues, Cache Hit Issues, DNS Info, Reports slowest Azure Red Code Tested
 
**Prerequisites & Setup**
1. Install PowerShell 7+:

https://learn.microsoft.com/enus/powershell/scripting/install/installing-powershell-onwindows?view=powershell-7.5

 
2. Open PS, and within OS Set execution policy: Set-ExecutionPolicy Unrestricted

Set-ExecutionPolicy Unrestricted

 
3. Download ps1 files and run script:

.\CheckCDNInfo_v10125.ps1

 
4. Enter an AFD URL

e.g., https://fp-afd.azureedge.net/apc/100k.gif
