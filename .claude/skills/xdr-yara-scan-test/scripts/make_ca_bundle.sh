#!/usr/bin/env bash
# Build a CA bundle so Python (requests) can verify TLS through a corporate proxy
# that MITMs outbound HTTPS. Needed only on the LOCAL test machine (macOS example);
# the XDR agent is unaffected. Prints the bundle path — export it as XDR_CA_BUNDLE.
#
#   export XDR_CA_BUNDLE="$(./make_ca_bundle.sh)"
set -euo pipefail
OUT="${1:-$(cd "$(dirname "$0")" && pwd)/xdr_ca_bundle.pem}"
: > "$OUT"
if [[ "$(uname)" == "Darwin" ]]; then
  security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain >> "$OUT" 2>/dev/null || true
  security find-certificate -a -p /Library/Keychains/System.keychain >> "$OUT" 2>/dev/null || true
fi
CERTIFI="$(python3 -c 'import certifi;print(certifi.where())' 2>/dev/null || true)"
[[ -n "$CERTIFI" && -f "$CERTIFI" ]] && cat "$CERTIFI" >> "$OUT"
echo "$OUT" >&2
echo "certs: $(grep -c 'BEGIN CERTIFICATE' "$OUT")" >&2
echo "$OUT"
