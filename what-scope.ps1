<#
.SYNOPSIS
    Identify which Netskope NewEdge POP (data center) is handling this
    host's traffic, and summarize the TLS certificate chain presented along
    the way.

.DESCRIPTION
    PowerShell port of what-scope.sh; the two are kept functionally
    equivalent.

    Queries the Netskope "notskope" utility page (https://notskope.com by
    default). That page only reports a POP when the domain is steered to
    Netskope; otherwise it says traffic is not being steered.

    Proxy: -Proxy wins; otherwise HTTPS_PROXY / https_proxy / ALL_PROXY /
    all_proxy (honoring NO_PROXY / no_proxy) from the environment; otherwise
    the system default proxy (Windows Internet Options / PAC).

    Trust: -CACert wins (only that bundle is trusted); otherwise the OS
    trust store is used (Windows certificate store, macOS keychains, Linux
    system CA bundle).

    Exit codes: 0 POP found, 1 not steered / no POP info, 2 usage error,
    3 request failed.

.PARAMETER Proxy
    Proxy URL (e.g. http://proxy.example:8080), overriding *_PROXY
    environment variables. Credentials may be embedded (http://user:pass@host:port).

.PARAMETER CACert
    CA bundle (PEM) to verify against instead of the OS trust store.

.PARAMETER Url
    Check page to query. Default: https://notskope.com

.PARAMETER Insecure
    Do not verify the server certificate.

.PARAMETER Timeout
    Overall request timeout in seconds. Default: 15

.PARAMETER Raw
    Also print the raw page text.

.EXAMPLE
    ./what-scope.ps1

.EXAMPLE
    ./what-scope.ps1 -x http://proxy.corp:8080 -c ./netskope-ca.pem
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Alias('x')][string]$Proxy,
    [Alias('c')][string]$CACert,
    [Alias('u')][string]$Url = 'https://notskope.com',
    [Alias('k')][switch]$Insecure,
    [Alias('t')][int]$Timeout = 15,
    [Alias('r')][switch]$Raw,
    [Alias('h')][switch]$Help,
    # Catches unknown arguments so they can be rejected with exit code 2.
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

if ($Help) {
    Get-Help -Detailed $PSCommandPath
    exit 0
}

function Fail([string]$Message) {
    [Console]::Error.WriteLine("what-scope.ps1: $Message")
    exit 2
}

# Hide credentials embedded in a proxy URL (scheme://user:pass@host).
function Redact([string]$s) {
    return ($s -replace '^([A-Za-z0-9+.-]+://)?[^@/]+@', '$1***@')
}

function Line([string]$Label, $Value) {
    '  {0,-18} {1}' -f $Label, $Value
}

if ($Rest) {
    [Console]::Error.WriteLine("Usage: what-scope.ps1 [-Proxy URL] [-CACert FILE] [-Url URL] [-Insecure] [-Timeout SECS] [-Raw] [-Help]")
    Fail "unknown argument: $($Rest -join ' ')"
}

try { $target = [Uri]$Url } catch { Fail "invalid URL: $Url" }
if (-not $target.IsAbsoluteUri) { Fail "invalid URL: $Url" }

# The request runs in compiled code: TLS validation callbacks fire on
# threads with no PowerShell runspace, so a scriptblock can't be used.
# Kept to C# 5 so it compiles under Windows PowerShell 5.1 too.
if (-not ('WhatScope.Probe' -as [type])) {
    Add-Type -IgnoreWarnings -WarningAction SilentlyContinue -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace WhatScope {
    public class Result {
        public int StatusCode;
        public string HttpVersion = "";
        public string Body = "";
        public string Error = "";
        public bool TlsFailure;
        public string Verify = "";
        public List<X509Certificate2> Chain = new List<X509Certificate2>();
    }

    public static class Probe {
        public static Result Fetch(string url, IWebProxy proxy, bool useProxy,
                                   X509Certificate2Collection anchors, bool insecure, int timeoutMs) {
            Result r = new Result();
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Timeout = timeoutMs;
            req.ReadWriteTimeout = timeoutMs;
            req.AllowAutoRedirect = true;
            req.UserAgent = "what-scope.ps1";
            if (useProxy) req.Proxy = proxy;
            req.ServerCertificateValidationCallback = delegate(object s, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
                r.Chain.Clear();
                if (chain != null) {
                    foreach (X509ChainElement e in chain.ChainElements)
                        r.Chain.Add(new X509Certificate2(e.Certificate.RawData));
                }
                if (r.Chain.Count == 0 && cert != null)
                    r.Chain.Add(new X509Certificate2(cert.GetRawCertData()));
                if (insecure) { r.Verify = "skipped"; return true; }
                bool ok;
                if (anchors != null) ok = VerifyAgainst(new X509Certificate2(cert.GetRawCertData()), chain, errors, anchors, r);
                else {
                    ok = errors == SslPolicyErrors.None;
                    r.Verify = ok ? "OK" : "FAILED (" + Describe(errors, chain) + ")";
                }
                if (!ok) r.TlsFailure = true;
                return ok;
            };
            HttpWebResponse resp = null;
            try {
                resp = (HttpWebResponse)req.GetResponse();
            } catch (WebException ex) {
                resp = ex.Response as HttpWebResponse;
                if (resp == null) {
                    r.Error = Flatten(ex);
                    return r;
                }
            } catch (Exception ex) {
                r.Error = Flatten(ex);
                return r;
            }
            using (resp) {
                r.StatusCode = (int)resp.StatusCode;
                r.HttpVersion = resp.ProtocolVersion.ToString();
                using (StreamReader sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                    r.Body = sr.ReadToEnd();
            }
            return r;
        }

        // Trust only the supplied anchors, like curl --cacert.
        static bool VerifyAgainst(X509Certificate2 leaf, X509Chain presented, SslPolicyErrors errors,
                                  X509Certificate2Collection anchors, Result r) {
            if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) {
                r.Verify = "FAILED (name mismatch)"; return false;
            }
            List<string> trusted = new List<string>();
            foreach (X509Certificate2 a in anchors) trusted.Add(a.Thumbprint.ToUpperInvariant());
            X509Chain c = new X509Chain();
            c.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            c.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            c.ChainPolicy.ExtraStore.AddRange(anchors);
            if (presented != null)
                foreach (X509ChainElement e in presented.ChainElements) c.ChainPolicy.ExtraStore.Add(e.Certificate);
            c.Build(leaf);
            foreach (X509ChainStatus st in c.ChainStatus) {
                if (st.Status != X509ChainStatusFlags.NoError &&
                    st.Status != X509ChainStatusFlags.UntrustedRoot &&
                    st.Status != X509ChainStatusFlags.PartialChain) {
                    r.Verify = "FAILED (" + st.Status + ")"; return false;
                }
            }
            foreach (X509ChainElement e in c.ChainElements) {
                if (trusted.Contains(e.Certificate.Thumbprint.ToUpperInvariant())) { r.Verify = "OK"; return true; }
            }
            r.Verify = "FAILED (chain does not lead to a --cacert anchor)";
            return false;
        }

        static string Describe(SslPolicyErrors errors, X509Chain chain) {
            List<string> parts = new List<string>();
            if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) parts.Add("name mismatch");
            if ((errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0) parts.Add("no certificate");
            if ((errors & SslPolicyErrors.RemoteCertificateChainErrors) != 0) {
                if (chain != null)
                    foreach (X509ChainStatus st in chain.ChainStatus)
                        if (st.Status != X509ChainStatusFlags.NoError) parts.Add(st.Status.ToString());
                if (parts.Count == 0) parts.Add("chain error");
            }
            return string.Join(", ", parts.ToArray());
        }

        static string Flatten(Exception ex) {
            List<string> msgs = new List<string>();
            for (Exception e = ex; e != null; e = e.InnerException)
                if (!msgs.Contains(e.Message)) msgs.Add(e.Message);
            return string.Join(" -> ", msgs.ToArray());
        }
    }
}
'@
}

# Windows PowerShell (.NET Framework) may not offer TLS 1.2/1.3 by default.
if ($PSVersionTable.PSEdition -ne 'Core') {
    $proto = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if ([enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
        $proto = $proto -bor [Net.SecurityProtocolType]'Tls13'
    }
    [Net.ServicePointManager]::SecurityProtocol = $proto
}

# ----------------------------------------------------------------- trust store
$anchors = $null
if ($Insecure) {
    $trustDesc = 'none (verification disabled)'
} elseif ($CACert) {
    if (-not (Test-Path -LiteralPath $CACert -PathType Leaf)) { Fail "cannot read CA bundle: $CACert" }
    $anchors = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $pem = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $CACert).ProviderPath)
    foreach ($m in [regex]::Matches($pem, '-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----')) {
        $der = [Convert]::FromBase64String(($m.Groups[1].Value -replace '\s', ''))
        [void]$anchors.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $der)))
    }
    if ($anchors.Count -eq 0) { Fail "no PEM certificates found in $CACert" }
    $trustDesc = "$CACert (from -CACert, $($anchors.Count) certs)"
} else {
    $os = if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) { 'Windows certificate store' }
          elseif ($IsMacOS) { 'macOS keychains' }
          else { 'system CA bundle' }
    $trustDesc = "OS trust store ($os)"
}

# ----------------------------------------------------------------------- proxy
function Test-NoProxy([string]$HostName, [string]$List) {
    foreach ($entry in ($List -split '[,\s]+')) {
        $e = $entry.Trim().ToLowerInvariant() -replace ':\d+$', ''
        if (-not $e) { continue }
        if ($e -eq '*') { return $true }
        $e = $e.TrimStart('*').TrimStart('.')
        $h = $HostName.ToLowerInvariant()
        if ($h -eq $e -or $h.EndsWith(".$e")) { return $true }
    }
    return $false
}

function New-Proxy([string]$ProxyUrl) {
    if ($ProxyUrl -notmatch '^[A-Za-z][A-Za-z0-9+.-]*://') { $ProxyUrl = "http://$ProxyUrl" }
    $pu = [Uri]$ProxyUrl
    $wp = New-Object System.Net.WebProxy(('{0}://{1}:{2}' -f $pu.Scheme, $pu.Host, $pu.Port))
    if ($pu.UserInfo) {
        $parts = $pu.UserInfo -split ':', 2
        $pass = if ($parts.Count -gt 1) { [Uri]::UnescapeDataString($parts[1]) } else { '' }
        $wp.Credentials = New-Object System.Net.NetworkCredential([Uri]::UnescapeDataString($parts[0]), $pass)
    }
    return $wp
}

$webProxy = $null
$useProxy = $true
if ($Proxy) {
    $webProxy = New-Proxy $Proxy
    $proxyDesc = "$(Redact $Proxy) (from -Proxy)"
} else {
    $names = if ($target.Scheme -eq 'https') { 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy' }
             else { 'http_proxy', 'HTTP_PROXY', 'ALL_PROXY', 'all_proxy' }
    $envName = $null
    foreach ($n in $names) {
        if ([Environment]::GetEnvironmentVariable($n)) { $envName = $n; break }
    }
    $noProxy = [Environment]::GetEnvironmentVariable('NO_PROXY')
    if (-not $noProxy) { $noProxy = [Environment]::GetEnvironmentVariable('no_proxy') }
    if ($envName) {
        $envVal = [Environment]::GetEnvironmentVariable($envName)
        $proxyDesc = "$(Redact $envVal) (from `$$envName)"
        if ($noProxy) { $proxyDesc += "; NO_PROXY=$noProxy" }
        if ($noProxy -and (Test-NoProxy $target.Host $noProxy)) {
            $proxyDesc += ' -> bypassed for this host'
            $webProxy = New-Object System.Net.WebProxy
        } else {
            $webProxy = New-Proxy $envVal
        }
    } else {
        # Leave the request's default proxy alone (Windows: Internet Options/PAC).
        $useProxy = $false
        $sys = [System.Net.WebRequest]::DefaultWebProxy
        $resolved = $null
        if ($sys -and $target.Scheme -match '^https?$') {
            try { if (-not $sys.IsBypassed($target)) { $resolved = $sys.GetProxy($target) } } catch { }
        }
        if ($resolved -and $resolved.AbsoluteUri -ne $target.AbsoluteUri) {
            $proxyDesc = "$(Redact $resolved.AbsoluteUri) (system default)"
        } else {
            $proxyDesc = 'none (direct)'
        }
    }
}

# --------------------------------------------------------------------- request
$result = $null
$endpoint = ''
if ($target.Scheme -eq 'file') {
    # Local file: lets a saved page be parsed offline, as curl does with file://.
    $result = New-Object WhatScope.Result
    try { $result.Body = [IO.File]::ReadAllText($target.LocalPath) } catch { $result.Error = $_.Exception.Message }
} else {
    $result = [WhatScope.Probe]::Fetch($target.AbsoluteUri, $webProxy, $useProxy, $anchors, [bool]$Insecure, $Timeout * 1000)
    $epHost = if ($webProxy -and $webProxy.Address) { $webProxy.Address.Host } else { $target.Host }
    try {
        $ip = [System.Net.Dns]::GetHostAddresses($epHost) | Select-Object -First 1
        $endpoint = "$epHost ($ip)"
    } catch { $endpoint = $epHost }
}

'== Request'
Line 'URL:' $target.AbsoluteUri
Line 'Proxy:' $proxyDesc
Line 'Trust store:' $trustDesc
if ($endpoint) { Line 'Endpoint:' $endpoint }
if ($result.StatusCode) { Line 'HTTP status:' ('{0} (HTTP/{1})' -f $result.StatusCode, $result.HttpVersion) }
$failed = [bool]$result.Error
if ($failed) {
    Line 'Error:' $result.Error
    if ($result.TlsFailure) {
        '  Hint: certificate verification failed. If traffic is SSL-inspected,'
        '        pass the inspecting CA with -CACert, or use -Insecure to inspect anyway.'
    }
}

# ------------------------------------------------------------------------- POP
''
'== Netskope POP'

# Flatten the HTML to lines of text so tags/newlines don't split matches.
$lines = @()
if ($result.Body) {
    $t = $result.Body -replace '[\r\n]', ' '
    $t = $t -replace '<br[^>]*>', "`n" -replace '</(td|tr|p|div)>', "`n" -replace '<[^>]+>', ''
    $t = $t -replace '&nbsp;', ' ' -replace '&amp;', '&'
    $lines = @($t -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Field([string]$Prefix) {
    foreach ($l in $lines) {
        if ($l.StartsWith($Prefix)) { return $l.Substring($Prefix.Length).Trim() }
    }
    return ''
}

$popLine = $lines | Where-Object { $_ -match 'Netskope NewEdge.*data center in' } | Select-Object -First 1
$status = 1
if ($popLine) {
    $location = $popLine -replace '.*data center in ', ''
    $popCode = if ($location -match '\(([A-Za-z0-9-]+)\)\s*$') { $Matches[1] } else { 'unknown' }
    $popCity = $location -replace '\s*\([^)]*\)\s*$', ''
    Line 'POP:' $popCode
    Line 'Location:' $popCity
    Line 'Source IP:' (Field 'Your source IP address is')
    Line 'XFF IP:' (Field 'Your XFF IP address is')
    Line 'HTTP (at POP):' (Field 'HTTP version is')
    Line 'TLS (at POP):' (Field 'Negotiated encryption is')
    $status = 0
} elseif ($notSteered = $lines | Where-Object { $_ -match 'not steering' } | Select-Object -First 1) {
    "  Not steered to Netskope (page reports: $notSteered)"
} elseif ($result.Body) {
    '  No POP information found in response.'
} else {
    '  No response body.'
}

# ---------------------------------------------------------------- certificates
''
'== Certificate chain'
if ($target.Scheme -ne 'https') {
    '  Not applicable (plain HTTP).'
} elseif ($result.Chain.Count -eq 0) {
    '  Not available (TLS handshake did not complete).'
} else {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    for ($i = 0; $i -lt $result.Chain.Count; $i++) {
        $cert = $result.Chain[$i]
        '  [{0}] Subject:  {1}' -f $i, $cert.Subject
        '      Issuer:   {0}' -f $cert.Issuer
        '      Serial:   {0}' -f $cert.SerialNumber.ToLowerInvariant()
        $san = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
        if ($san) {
            $s = $san.Format($false)
            if ($s.Length -gt 200) { $s = $s.Substring(0, 200) + '...' }
            '      SAN:      {0}' -f $s
        }
        '      Valid:    {0:u}  ->  {1:u}' -f $cert.NotBefore.ToUniversalTime(), $cert.NotAfter.ToUniversalTime()
    }
    $fp = ($sha.ComputeHash($result.Chain[0].RawData) | ForEach-Object { $_.ToString('X2') }) -join ':'
    "  Leaf SHA-256: $fp"

    $issuers = ($result.Chain | ForEach-Object { $_.Issuer }) -join "`n"
    if ($issuers -match '(?i)netskope') {
        '  SSL inspection: YES - chain issued by a Netskope CA'
    } elseif ($issuers -match '(?i)goskope|ssl inspection|forward ?proxy|zscaler|palo alto|fortinet|bluecoat|symantec web') {
        '  SSL inspection: likely - chain issued by a proxy/inspection CA'
    } else {
        '  SSL inspection: not detected (publicly issued chain)'
    }
    if (-not $Insecure -and $result.Verify) { "  Verification:   $($result.Verify)" }
}

if ($Raw -and $lines.Count) {
    ''
    '== Raw page text'
    $lines | Where-Object { $_ -notmatch 'PADDING TO ENSURE' } | ForEach-Object { "  $_" }
}

if ($failed) { exit 3 }
exit $status
