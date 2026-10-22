#!/usr/bin/env bash
#
# what-scope.sh - identify which Netskope NewEdge POP (data center) is
# handling this host's traffic, and summarize the TLS certificate chain
# presented along the way.
#
# Queries the Netskope "notskope" utility page (https://notskope.com by
# default). That page only reports a POP when the domain is steered to
# Netskope; otherwise it says traffic is not being steered.
#
# Proxy:      --proxy wins; otherwise curl honors HTTPS_PROXY / https_proxy /
#             ALL_PROXY / all_proxy / NO_PROXY from the environment.
# Trust:      --cacert wins; otherwise macOS keychains (system roots, System,
#             login) are exported to a temporary bundle, and on Linux the
#             system CA bundle is used.

set -euo pipefail

PROG=${0##*/}
URL="https://notskope.com"
PROXY=""
CACERT=""
INSECURE=0
TIMEOUT=15
RAW=0

usage() {
	cat <<EOF
Usage: $PROG [options]

Identify the Netskope NewEdge POP in use and show certificate basics.

Options:
  -x, --proxy URL      Use this proxy (e.g. http://proxy.example:8080),
                       overriding *_PROXY environment variables
  -c, --cacert FILE    CA bundle (PEM) to verify against instead of the
                       OS trust store
  -u, --url URL        Check page to query (default: $URL)
  -k, --insecure       Do not verify the server certificate
  -t, --timeout SECS   Overall request timeout (default: $TIMEOUT)
  -r, --raw            Also print the raw page text
  -h, --help           Show this help
EOF
}

die() {
	echo "$PROG: $*" >&2
	exit 2
}

# Hide credentials embedded in a proxy URL (scheme://user:pass@host).
redact() {
	sed -E 's#^([A-Za-z0-9+.-]+://)?[^@/]+@#\1***@#'
}

while [ $# -gt 0 ]; do
	case "$1" in
	-x | --proxy)
		[ $# -ge 2 ] || die "$1 requires an argument"
		PROXY=$2
		shift 2
		;;
	-c | --cacert)
		[ $# -ge 2 ] || die "$1 requires an argument"
		CACERT=$2
		shift 2
		;;
	-u | --url)
		[ $# -ge 2 ] || die "$1 requires an argument"
		URL=$2
		shift 2
		;;
	-t | --timeout)
		[ $# -ge 2 ] || die "$1 requires an argument"
		TIMEOUT=$2
		shift 2
		;;
	-k | --insecure)
		INSECURE=1
		shift
		;;
	-r | --raw)
		RAW=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		die "unknown argument: $1"
		;;
	esac
done

command -v curl >/dev/null 2>&1 || die "curl is required"

TMPDIR_RUN=$(mktemp -d "${TMPDIR:-/tmp}/what-scope.XXXXXX")
trap 'rm -rf "$TMPDIR_RUN"' EXIT

# ---------------------------------------------------------------- trust store
TRUST_DESC=""
CURL_TRUST=()

if [ "$INSECURE" -eq 1 ]; then
	TRUST_DESC="none (verification disabled)"
	CURL_TRUST=(--insecure)
elif [ -n "$CACERT" ]; then
	[ -r "$CACERT" ] || die "cannot read CA bundle: $CACERT"
	TRUST_DESC="$CACERT (from --cacert)"
	CURL_TRUST=(--cacert "$CACERT")
else
	case "$(uname -s)" in
	Darwin)
		bundle="$TMPDIR_RUN/macos-keychain.pem"
		keychains=()
		for kc in \
			/System/Library/Keychains/SystemRootCertificates.keychain \
			/Library/Keychains/System.keychain \
			"$HOME/Library/Keychains/login.keychain-db"; do
			[ -e "$kc" ] && keychains+=("$kc")
		done
		if [ ${#keychains[@]} -gt 0 ] &&
			security find-certificate -a -p "${keychains[@]}" >"$bundle" 2>/dev/null &&
			[ -s "$bundle" ]; then
			n=$(grep -c 'BEGIN CERTIFICATE' "$bundle" || true)
			TRUST_DESC="macOS keychains ($n certs exported)"
			CURL_TRUST=(--cacert "$bundle")
		else
			TRUST_DESC="curl default (keychain export failed)"
		fi
		;;
	Linux)
		for f in \
			/etc/ssl/certs/ca-certificates.crt \
			/etc/pki/tls/certs/ca-bundle.crt \
			/etc/ssl/ca-bundle.pem \
			/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
			/etc/ssl/cert.pem; do
			if [ -r "$f" ]; then
				TRUST_DESC="system bundle $f"
				CURL_TRUST=(--cacert "$f")
				break
			fi
		done
		[ -n "$TRUST_DESC" ] || TRUST_DESC="curl default (no system bundle found)"
		;;
	*)
		TRUST_DESC="curl default"
		;;
	esac
fi

# ---------------------------------------------------------------------- proxy
CURL_PROXY=()
if [ -n "$PROXY" ]; then
	PROXY_DESC="$(printf '%s' "$PROXY" | redact) (from --proxy)"
	# --noproxy '' so NO_PROXY in the environment can't bypass an explicit proxy.
	CURL_PROXY=(--proxy "$PROXY" --noproxy '')
else
	envp=""
	envname=""
	case "$URL" in
	https://*) names="HTTPS_PROXY https_proxy ALL_PROXY all_proxy" ;;
	*) names="http_proxy HTTP_PROXY ALL_PROXY all_proxy" ;;
	esac
	for v in $names; do
		if [ -n "${!v:-}" ]; then
			envp=${!v}
			envname=$v
			break
		fi
	done
	if [ -n "$envp" ]; then
		PROXY_DESC="$(printf '%s' "$envp" | redact) (from \$$envname)"
		nop="${NO_PROXY:-${no_proxy:-}}"
		[ -n "$nop" ] && PROXY_DESC="$PROXY_DESC; NO_PROXY=$nop"
	else
		PROXY_DESC="none (direct)"
	fi
fi

# -------------------------------------------------------------------- request
BODY="$TMPDIR_RUN/body.html"
META="$TMPDIR_RUN/meta.txt"
ERR="$TMPDIR_RUN/err.txt"

WOUT='remote_ip=%{remote_ip}\nhttp_code=%{http_code}\nhttp_version=%{http_version}\nssl_verify=%{ssl_verify_result}\n--CERTS--\n%{certs}'

set +e
curl -sS -L --max-time "$TIMEOUT" \
	${CURL_PROXY[@]+"${CURL_PROXY[@]}"} \
	${CURL_TRUST[@]+"${CURL_TRUST[@]}"} \
	-o "$BODY" -w "$WOUT" "$URL" >"$META" 2>"$ERR"
rc=$?
set -e

meta() { sed -n "s/^$1=//p" "$META" | head -1; }

echo "== Request"
printf '  %-18s %s\n' "URL:" "$URL"
printf '  %-18s %s\n' "Proxy:" "$PROXY_DESC"
printf '  %-18s %s\n' "Trust store:" "$TRUST_DESC"
printf '  %-18s %s\n' "Connected to:" "$(meta remote_ip)"
printf '  %-18s %s\n' "HTTP status:" "$(meta http_code) (HTTP/$(meta http_version))"

if [ "$rc" -ne 0 ]; then
	printf '  %-18s curl exit %s: %s\n' "Error:" "$rc" "$(tr -d '\n' <"$ERR")"
	case "$rc" in
	60 | 35 | 58 | 77)
		echo "  Hint: certificate verification failed. If traffic is SSL-inspected,"
		echo "        pass the inspecting CA with --cacert, or use -k to inspect anyway."
		;;
	esac
fi

# ------------------------------------------------------------------------ POP
echo
echo "== Netskope POP"

# Flatten the HTML to one line of text so tags/newlines don't split matches.
text=""
if [ -s "$BODY" ]; then
	text=$(tr '\n' ' ' <"$BODY" | sed -E 's/<br[^>]*>/\n/g; s/<\/(td|tr|p|div)>/\n/g; s/<[^>]+>//g; s/&nbsp;/ /g; s/&amp;/\&/g' |
		sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' | grep -v '^$' || true)
fi

pop_line=$(printf '%s\n' "$text" | grep -m1 'Netskope NewEdge.*data center in' || true)
if [ -n "$pop_line" ]; then
	location=$(printf '%s\n' "$pop_line" | sed -E 's/.*data center in //')
	pop_code=$(printf '%s\n' "$location" | sed -nE 's/.*\(([A-Za-z0-9-]+)\)[[:space:]]*$/\1/p')
	pop_city=$(printf '%s\n' "$location" | sed -E 's/[[:space:]]*\([^)]*\)[[:space:]]*$//')
	field() { printf '%s\n' "$text" | sed -nE "s/^$1[[:space:]]*//p" | head -1; }
	printf '  %-18s %s\n' "POP:" "${pop_code:-unknown}"
	printf '  %-18s %s\n' "Location:" "$pop_city"
	printf '  %-18s %s\n' "Source IP:" "$(field 'Your source IP address is')"
	printf '  %-18s %s\n' "XFF IP:" "$(field 'Your XFF IP address is')"
	printf '  %-18s %s\n' "HTTP (at POP):" "$(field 'HTTP version is')"
	printf '  %-18s %s\n' "TLS (at POP):" "$(field 'Negotiated encryption is')"
	status=0
elif printf '%s\n' "$text" | grep -qi 'not steering'; then
	echo "  Not steered to Netskope (page reports: $(printf '%s\n' "$text" | grep -i -m1 'not steering'))"
	status=1
elif [ -s "$BODY" ]; then
	echo "  No POP information found in response."
	status=1
else
	echo "  No response body."
	status=1
fi

# ------------------------------------------------------------- certificates
echo
echo "== Certificate chain"

# curl's %{certs} emits "Field:value" lines per certificate (OpenSSL,
# LibreSSL and SecureTransport backends); OpenSSL builds also include a
# PEM "Cert:" block. Each certificate starts at its Subject: line.
certs=$(sed -n '/^--CERTS--$/,$p' "$META" | sed 1d)
if [ -z "$certs" ]; then
	case "$URL" in
	https://*) echo "  Not available (needs curl >= 7.88, or TLS handshake failed)." ;;
	*) echo "  Not applicable (plain HTTP)." ;;
	esac
else
	printf '%s\n' "$certs" | awk '
		/^Subject:/        { n++; printf "  [%d] Subject:  %s\n", n-1, substr($0, 9); next }
		/^Issuer:/         { printf "      Issuer:   %s\n", substr($0, 8); next }
		/^Serial Number:/  { printf "      Serial:   %s\n", substr($0, 15); next }
		/^Start date:/     { printf "      Valid:    %s", substr($0, 12); next }
		/^Expire date:/    { printf "  ->  %s\n", substr($0, 13); next }
		/^X509v3 Subject Alternative Name:/ {
			san = substr($0, 33); if (length(san) > 200) san = substr(san, 1, 200) "..."
			printf "      SAN:      %s\n", san; next }
	'

	# SHA-256 fingerprint of the leaf, when curl provided PEM and openssl exists.
	if command -v openssl >/dev/null 2>&1 &&
		printf '%s\n' "$certs" | grep -q 'BEGIN CERTIFICATE'; then
		leaf_fp=$(printf '%s\n' "$certs" | sed 's/^Cert://' |
			sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/{p;/END CERTIFICATE/q;}' |
			openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')
		[ -n "$leaf_fp" ] && printf '  Leaf SHA-256: %s\n' "$leaf_fp"
	fi

	issuers=$(printf '%s\n' "$certs" | sed -n 's/^Issuer://p')
	if printf '%s\n' "$issuers" | grep -qi 'netskope'; then
		echo "  SSL inspection: YES - chain issued by a Netskope CA"
	elif printf '%s\n' "$issuers" | grep -qiE 'goskope|ssl inspection|forward ?proxy|zscaler|palo alto|fortinet|bluecoat|symantec web'; then
		echo "  SSL inspection: likely - chain issued by a proxy/inspection CA"
	else
		echo "  SSL inspection: not detected (publicly issued chain)"
	fi
	sv=$(meta ssl_verify)
	if [ "$INSECURE" -eq 0 ] && [ -n "$sv" ]; then
		[ "$sv" = "0" ] && echo "  Verification:   OK" || echo "  Verification:   FAILED (code $sv)"
	fi
fi

if [ "$RAW" -eq 1 ] && [ -n "$text" ]; then
	echo
	echo "== Raw page text"
	printf '%s\n' "$text" | grep -v 'PADDING TO ENSURE' | sed 's/^/  /'
fi

[ "$rc" -eq 0 ] || exit 3
exit "$status"
