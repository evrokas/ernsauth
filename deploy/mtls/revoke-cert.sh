#!/usr/bin/env bash
# Revoke a client certificate (by name or serial) and rebuild the CRL.
#
#   revoke-cert.sh <name|serial>
#
# Revoking only edits the CA's own records. The server keeps accepting the
# certificate until the NEW crl.pem is installed there and Apache reloaded
# -- the last lines of output say how.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$here/common.sh"

[ $# -eq 1 ] || die "usage: revoke-cert.sh <name|serial>"
target="$1"
need_ca

# index.txt columns: status, expiry, revocation, serial, filename, subject
serial=""
if [[ "$target" =~ ^[0-9A-Fa-f]+$ ]] && awk -F'\t' -v s="${target^^}" '$1=="V" && $4==s {f=1} END{exit !f}' "$CA_DIR/index.txt"; then
    serial="${target^^}"
else
    mapfile -t hits < <(awk -F'\t' -v n="/CN=$target" '$1=="V" && $6==n {print $4}' "$CA_DIR/index.txt")
    [ "${#hits[@]}" -ge 1 ] || die "no valid certificate named or numbered '$target' (see list-certs.sh)"
    [ "${#hits[@]}" -eq 1 ] || die "several valid certificates are named '$target' -- revoke by serial: ${hits[*]}"
    serial="${hits[0]}"
fi

# shellcheck disable=SC2046
openssl ca -config "$CA_CNF" $(ca_passin) -revoke "$CA_DIR/newcerts/$serial.pem"
"$here/refresh-crl.sh"
