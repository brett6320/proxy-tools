# proxy-tools

Small diagnostics for traffic that passes through a cloud proxy.

## what-scope

Shows which **Netskope NewEdge POP** (data center) is handling your traffic.
It also summarizes the TLS certificate chain your client was given, so you
can see whether the connection is being SSL-inspected.

It comes in two versions with the same behavior:

| Script | Runs on | Needs |
| --- | --- | --- |
| `what-scope.sh` | macOS, Linux (bash 3.2+) | `curl` 7.88+ (for the certificate chain); `openssl` optional (leaf fingerprint) |
| `what-scope.ps1` | Windows PowerShell 5.1, PowerShell 7+ on Windows / macOS / Linux | nothing extra |

### How it works

The script fetches Netskope's check page, `https://notskope.com`. When that
domain is steered to Netskope, the page names the POP that served it and
shows what the POP saw: your source IP, your X-Forwarded-For IP, the HTTP
version and the TLS cipher. When the domain is not steered, the page says so,
and the script reports "Not steered to Netskope".

The certificate chain comes from the same request, so it is the chain your
client actually received, whether the connection went direct or through a
proxy. If any certificate in the chain was issued by a Netskope CA, the
script reports that SSL inspection is on.

### Usage

```sh
./what-scope.sh                                   # env proxy vars + OS trust store
./what-scope.sh -x http://proxy.corp:8080         # explicit proxy
./what-scope.sh -c ./netskope-ca.pem              # verify against a specific CA bundle
./what-scope.sh -k                                # don't verify (inspect a failing chain)
```

```powershell
./what-scope.ps1
./what-scope.ps1 -Proxy http://proxy.corp:8080    # or -x
./what-scope.ps1 -CACert .\netskope-ca.pem        # or -c
./what-scope.ps1 -Insecure                        # or -k
Get-Help ./what-scope.ps1 -Detailed
```

On Windows, if scripts are blocked by execution policy, run it with
`powershell -ExecutionPolicy Bypass -File .\what-scope.ps1`.

### Options

| bash | PowerShell | Meaning |
| --- | --- | --- |
| `-x`, `--proxy URL` | `-Proxy`, `-x` | Use this proxy. It overrides the `*_PROXY` variables and `NO_PROXY`. Credentials can go in the URL (`http://user:pass@host:port`). |
| `-c`, `--cacert FILE` | `-CACert`, `-c` | Trust **only** the CA certificates in this PEM bundle instead of the OS trust store. |
| `-u`, `--url URL` | `-Url`, `-u` | Page to check (default `https://notskope.com`). A `file://` URL parses a saved page offline. |
| `-k`, `--insecure` | `-Insecure`, `-k` | Skip certificate verification. |
| `-t`, `--timeout SECS` | `-Timeout`, `-t` | Request timeout (default 15). |
| `-r`, `--raw` | `-Raw`, `-r` | Also print the page text. |
| `-h`, `--help` | `-Help`, `-h` | Help. |

### Which proxy is used

1. `--proxy` / `-Proxy`, if given.
2. Otherwise, for https URLs, the first variable that is set out of
   `HTTPS_PROXY`, `https_proxy`, `ALL_PROXY`, `all_proxy`. For http URLs,
   `http_proxy`, `HTTP_PROXY`, `ALL_PROXY`, `all_proxy`. `NO_PROXY` /
   `no_proxy` is honored: `*`, an exact host, or a domain suffix such as
   `.example.com`. The output says when the target host is bypassed.
3. Otherwise:
   - bash connects directly.
   - PowerShell uses the system default proxy. On Windows that is the
     Internet Options / PAC setting.

Credentials in a proxy URL are never printed; they show as `***@`.

### Which certificates are trusted

| Platform | Default | With `--cacert` / `-CACert` |
| --- | --- | --- |
| macOS (bash) | Certificates exported from the System Roots, System and login keychains to a temp bundle, deleted on exit | That bundle only |
| Linux (bash) | First system bundle found (`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, ...) | That bundle only |
| PowerShell (any OS) | The OS trust store as .NET uses it: Windows certificate store, macOS keychain, Linux OpenSSL store | That bundle only |

"That bundle only" is enforced:

- **bash:** passes an empty `--capath`, so Debian-style curl builds can't fall
  back to `/etc/ssl/certs`. It also sets `OPENSSL_X509_TEA_DISABLE=1`, so
  Apple's curl can't fall back to the keychain.
- **PowerShell:** accepts the server only if the chain it builds reaches a
  certificate in the bundle and the hostname matches.

Using the OS trust store matters on managed machines. The Netskope client
installs its inspection CA into the OS store. With the default trust,
inspected connections verify; with a public-only bundle, they fail.

### Output

Illustrative output (addresses and issuer are examples):

```
== Request
  URL:               https://notskope.com
  Proxy:             http://***@proxy.corp:8080 (from $HTTPS_PROXY)
  Trust store:       macOS keychains (193 certs exported)
  Connected to:      203.0.113.10
  HTTP status:       200 (HTTP/2)

== Netskope POP
  POP:               MIA2
  Location:          Miami, United States
  Source IP:         198.51.100.7
  XFF IP:            192.0.2.44
  HTTP (at POP):     HTTP/1.1
  TLS (at POP):      TLSv1.3/TLS_AES_256_GCM_SHA384

== Certificate chain
  [0] Subject:  CN = notskope.com
      Issuer:   ... O = Netskope Inc ...
      Serial:   ...
      SAN:      DNS:notskope.com, DNS:www.notskope.com
      Valid:    ...  ->  ...
  [1] ...
  Leaf SHA-256: C6:85:...
  SSL inspection: YES - chain issued by a Netskope CA
  Verification:   OK
```

If verification fails, both versions still print the chain. bash gets it
from a second, unverified handshake and discards the page from it;
PowerShell captures it during the failed handshake. You can see which CA
was presented and pass it with `--cacert`.

Small differences between the two versions:

- **Chain:** bash lists the certificates the server sent. PowerShell lists
  the chain .NET built, which ends at the trusted root (self-signed).
- **Connection line:** bash shows the IP it connected to (`Connected to`).
  PowerShell shows the host and its resolved IP (`Endpoint`); that is the
  proxy when one is used.
- **HTTP version:** curl may use HTTP/2; PowerShell's `HttpWebRequest`
  uses HTTP/1.1.
- **Formats:** names are printed as `CN = x, O = y` by curl and `CN=x, O=y`
  by .NET. Dates differ in format too.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | POP identified |
| 1 | Not steered to Netskope, or no POP info in the response |
| 2 | Usage error |
| 3 | Request failed (connection, proxy, TLS verification) |

## Development

`what-scope.sh` and `what-scope.ps1` must stay functionally equivalent. A
change to one (an option, the parsing, the output, an exit code) goes into
the other and this README in the same change.

`tests/run-linux.sh` runs both scripts through the same cases (saved
sample page, live fetch, right and wrong CA bundle, insecure, explicit proxy,
env proxy, `NO_PROXY` bypass, bad arguments) in the `mcr.microsoft.com/dotnet/sdk`
container, which ships `pwsh`, `curl` and `bash`:

```sh
tests/run-linux.sh
```

It needs Docker and network access. Saved pages go in `samples/`, which git
ignores; the suite needs `samples/notskope.html`. Untested so far: a live
Netskope-steered connection and Windows PowerShell 5.1.

## License

For internal use only: you may use, run, copy and modify it within your own
organization. Using it to support or provide services to clients or
customers requires a specific, express license from the author, and
distributing it requires the author's written permission. See
[LICENSE](LICENSE) for the terms.
