#!/usr/bin/env bash
# Rebuild crl.pem. Run it after every revocation AND on a schedule (at
# least every 60 days) even when nothing was revoked: an expired CRL makes
# Apache refuse every certificate, which locks you out of the dashboard.
#
#   refresh-crl.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$here/common.sh"
need_ca

# shellcheck disable=SC2046
openssl ca -config "$CA_CNF" $(ca_passin) -gencrl -out "$CA_DIR/crl.pem"

echo
echo "CRL written: $CA_DIR/crl.pem"
openssl crl -in "$CA_DIR/crl.pem" -noout -nextupdate
echo
echo "Install it on the server (Apache reads the CRL only at reload, so the"
echo "revocation is NOT in force until this has run):"
echo "  scp $CA_DIR/crl.pem $CA_DIR/ca.crt you@server:/tmp/"
echo "  ssh you@server 'sudo /path/to/ernsauth/deploy/mtls/server-install-crl.sh /tmp/crl.pem /tmp/ca.crt'"
