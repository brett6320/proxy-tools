#!/usr/bin/env bash
#
# Run what-scope.sh and what-scope.ps1 through the same cases on Linux, in a
# container that has bash, curl and pwsh. Needs Docker and network access.
#
#   tests/run-linux.sh            # run the suite
#   IMAGE=... tests/run-linux.sh  # use another image with bash+curl+pwsh

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=${IMAGE:-mcr.microsoft.com/dotnet/sdk:8.0}

[ -f "$ROOT/samples/notskope.html" ] || {
	echo "missing samples/notskope.html (a saved notskope.com page that shows a POP)" >&2
	exit 2
}

# Pin the platform to the Docker host's own architecture, so Docker doesn't
# pull a variant that has to run under emulation.
case "$(docker info --format '{{.Architecture}}' 2>/dev/null)" in
aarch64 | arm64) PLATFORM=linux/arm64 ;;
*) PLATFORM=linux/amd64 ;;
esac

exec docker run --rm --platform "$PLATFORM" -v "$ROOT":/w:ro -w /w "$IMAGE" bash -c '
set -u
B=/etc/ssl/certs/ca-certificates.crt
# A one-CA bundle with no ISRG/Let'"'"'s Encrypt root: verification must fail.
awk "/BEGIN CERT/{c++} c==5{print} /END CERT/{if(c==5) exit}" $B >/tmp/wrong-ca.txt

PASS=0 FAIL=0
# check NAME EXPECTED_RC REGEX -- CMD...   (REGEX "" = no output check)
check() {
	local name=$1 want=$2 re=$3; shift 4
	local out rc
	out=$("$@" 2>&1); rc=$?
	if [ "$rc" = "$want" ] && { [ -z "$re" ] || printf "%s\n" "$out" | grep -Eq "$re"; }; then
		PASS=$((PASS+1)); echo "ok   $name"
	else
		FAIL=$((FAIL+1)); echo "FAIL $name (rc=$rc want=$want, /$re/)"; printf "%s\n" "$out" | sed "s/^/     | /"
	fi
}

for impl in sh ps; do
	if [ $impl = sh ]; then T="./what-scope.sh"; else T="pwsh -NoProfile -NonInteractive -File ./what-scope.ps1"; fi
	check "$impl sample POP"         0 "POP: +MIA2"                    -- $T -u file:///w/samples/notskope.html
	check "$impl sample location"    0 "Location: +Miami, United States" -- $T -u file:///w/samples/notskope.html
	check "$impl sample XFF"         0 "XFF IP: +47\.207\.3\.187"      -- $T -u file:///w/samples/notskope.html
	check "$impl live not steered"   1 "Not steered to Netskope"       -- $T
	check "$impl live chain"         1 "Leaf SHA-256: [0-9A-F:]{95}"   -- $T
	check "$impl good cacert"        1 "Verification: +OK"             -- $T -c $B
	check "$impl wrong cacert fails" 3 "Verification: +FAILED"         -- $T -c /tmp/wrong-ca.txt
	check "$impl insecure"           1 "Trust store: +none"            -- $T -k -c /tmp/wrong-ca.txt
	check "$impl proxy arg redacted" 3 "Proxy: +http://\*\*\*@127\.0\.0\.1:9 " -- $T -t 3 -x http://user:secret@127.0.0.1:9
	check "$impl env proxy"          3 "from \\\$HTTPS_PROXY"          -- env HTTPS_PROXY=http://127.0.0.1:9 $T -t 3
	check "$impl NO_PROXY bypass"    1 "bypassed for this host"        -- env HTTPS_PROXY=http://127.0.0.1:9 NO_PROXY=.notskope.com $T -t 5
	check "$impl proxy arg beats NO_PROXY" 3 ""                        -- env NO_PROXY="*" $T -t 3 -x http://127.0.0.1:9
	check "$impl bad argument"       2 "unknown argument"              -- $T --bogus
done

echo "passed $PASS, failed $FAIL"
[ $FAIL -eq 0 ]
'
