#!/usr/bin/env bash
# Issue a client certificate for ONE device and export it as a .p12 for
# installing on that device (iPhone: AirDrop it, tap it, Settings -> Install).
#
#   issue-cert.sh <name> [--days N] [--legacy]
#
#   <name>     letters, digits, . _ -   (e.g. evangelos-iphone)
#   --days N   validity, default 365, max 730
#   --legacy   export the .p12 with the old PBE-SHA1-3DES algorithms, for
#              the case where an Apple device refuses an OpenSSL 3 export
#
# One certificate per device, never shared: that is what lets you revoke a
# lost phone without touching the others.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$here/common.sh"

name=""; days=365; legacy=0
while [ $# -gt 0 ]; do
    case "$1" in
        --days)   days="${2:-}"; shift 2 ;;
        --legacy) legacy=1; shift ;;
        -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}"; exit 0 ;;
        -*) die "unknown option: $1" ;;
        *) [ -z "$name" ] || die "only one <name> allowed"; name="$1"; shift ;;
    esac
done
[ -n "$name" ] || die "usage: issue-cert.sh <name> [--days N] [--legacy]"
[[ "$name" =~ ^[A-Za-z0-9._-]{1,48}$ ]] || die "name must be 1-48 chars of letters, digits, . _ -"
[[ "$days" =~ ^[0-9]+$ ]] && [ "$days" -ge 1 ] && [ "$days" -le 730 ] || die "--days must be 1-730"
need_ca

# Two live certificates with the same name make "which one do I revoke?"
# ambiguous -- revoke the old one first.
if grep -qE "^V	[^	]*		[^	]*	[^	]*	/CN=$name\$" "$CA_DIR/index.txt"; then
    die "a valid certificate named '$name' already exists -- revoke it first (revoke-cert.sh $name)"
fi

umask 077
out="$CA_DIR/issued/$name"
[ ! -e "$out" ] || die "$out already exists -- pick another name"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

openssl genrsa -out "$work/dev.key" 3072 2>/dev/null
openssl req -new -key "$work/dev.key" -subj "/CN=$name" -out "$work/dev.csr"
# shellcheck disable=SC2046
openssl ca -config "$CA_CNF" -extensions client_ext $(ca_passin) \
    -in "$work/dev.csr" -out "$work/dev.crt" -days "$days" -notext -batch

serial="$(openssl x509 -in "$work/dev.crt" -noout -serial | cut -d= -f2)"
mkdir -p "$out"

p12opts=()
[ "$legacy" -eq 1 ] && p12opts=(-legacy)
# The export password is typed on the device when the .p12 is installed.
# Empty passwords are rejected by iOS.
if [ -n "${ERNSAUTH_P12_PASS:-}" ]; then
    openssl pkcs12 -export "${p12opts[@]}" -inkey "$work/dev.key" -in "$work/dev.crt" \
        -certfile "$CA_DIR/ca.crt" -name "ErnsAuth $name" \
        -passout env:ERNSAUTH_P12_PASS -out "$out/$name.p12"
else
    openssl pkcs12 -export "${p12opts[@]}" -inkey "$work/dev.key" -in "$work/dev.crt" \
        -certfile "$CA_DIR/ca.crt" -name "ErnsAuth $name" -out "$out/$name.p12"
fi
cp "$work/dev.crt" "$out/$name.crt"

# Verify what was actually issued, don't just trust the command succeeded.
openssl x509 -in "$out/$name.crt" -noout -text | grep -q 'CA:FALSE' || die "issued certificate is not CA:FALSE"
openssl x509 -in "$out/$name.crt" -noout -text | grep -q 'TLS Web Client Authentication' || die "issued certificate lacks clientAuth"

# The private key only ever existed in $work (removed on exit) and inside
# the .p12.
echo
echo "Issued '$name'  serial $serial  expires $(openssl x509 -in "$out/$name.crt" -noout -enddate | cut -d= -f2)"
echo "  $out/$name.p12   <- install on the device, then DELETE every copy of it"
echo "Never email the .p12. Revoke with: revoke-cert.sh $name"
