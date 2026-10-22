#!/bin/sh
# Regenerate ta_certs.h (the TLS trust anchors used by stream.c) from
# curl's extract of the Mozilla CA bundle.
#
# Usage: update-ta-certs.sh [cacert.pem]
#
# Without an argument the latest bundle is fetched from curl.se. Roots
# whose subject matches an entry in EXCLUDE are dropped before brssl
# converts the rest to C.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
bearssl=$here/BearSSL
out=$here/ta_certs.h

# One extended regex per line, matched against the RFC 2253 subject.
#
# eMudhra / emSign: eight intermediates had weak, recoverable keys (Oct
# 2026). Browsers block them via OneCRL/CRLSets and the roots stay in the
# Mozilla bundle, but BearSSL does no revocation checking, so the only
# way to stop trusting them is to drop the roots.
# https://cycle.io/blog/2026-intermediate-ca-compromise
EXCLUDE='
O=eMudhra
'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ $# -ge 1 ]; then
    cp "$1" "$tmp/cacert.pem"
else
    curl -fsSL -o "$tmp/cacert.pem" https://curl.se/ca/cacert.pem
fi

make -s -C "$bearssl" BUILD="$tmp/bearssl" tools >&2

# Split the bundle into one file per certificate
awk -v dir="$tmp" '
/-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/cert%04d.pem", dir, n) }
f { print > f }
/-----END CERTIFICATE-----/ { close(f); f = "" }
' "$tmp/cacert.pem"

printf '%s\n' "$EXCLUDE" | grep -v '^$' > "$tmp/exclude"

: > "$tmp/filtered.pem"
kept=0
dropped=0
for c in "$tmp"/cert*.pem; do
    subj=$(openssl x509 -in "$c" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
    if printf '%s\n' "$subj" | grep -qE -f "$tmp/exclude"; then
        echo "excluding: $subj" >&2
        dropped=$((dropped + 1))
    else
        cat "$c" >> "$tmp/filtered.pem"
        kept=$((kept + 1))
    fi
done

"$tmp/bearssl/brssl" ta -q "$tmp/filtered.pem" > "$tmp/ta_certs.h"
mv "$tmp/ta_certs.h" "$out"
echo "wrote $out: $kept trust anchors ($dropped excluded)" >&2
