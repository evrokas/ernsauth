#!/usr/bin/env bash
# Run ON THE SERVER: install a new crl.pem (and ca.crt) for Apache, after
# checking they are sane, then reload Apache.
#
#   sudo server-install-crl.sh <crl.pem> [ca.crt]
#
# The checks matter: installing a CRL that is expired, or not signed by the
# installed CA, makes Apache refuse every certificate -- including yours.
set -euo pipefail

CA_TARGET="${ERNSAUTH_SERVER_CA_DIR:-/etc/ssl/ernsauth-ca}"
RELOAD="${ERNSAUTH_RELOAD_CMD:-systemctl reload apache2}"
TEST="${ERNSAUTH_TEST_CMD:-apachectl configtest}"

die() { echo "error: $*" >&2; exit 1; }

[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: server-install-crl.sh <crl.pem> [ca.crt]"
crl="$1"; ca="${2:-$CA_TARGET/ca.crt}"
[ -f "$crl" ] || die "$crl not found"
[ -f "$ca" ]  || die "$ca not found"

# Signed by this CA?
# (openssl crl exits 0 even when verification fails, so read its verdict.)
openssl crl -in "$crl" -CAfile "$ca" -noout 2>&1 | grep -q '^verify OK' \
    || die "$crl is not signed by $ca -- refusing to install"
# Not already (or about to be) expired? Require at least 7 days of life.
openssl crl -in "$crl" -noout -nextupdate | grep -q . || die "CRL has no nextUpdate"
nextupdate="$(openssl crl -in "$crl" -noout -nextupdate | cut -d= -f2)"
if ! openssl x509 -in "$ca" -noout -checkend 0 >/dev/null; then die "$ca has expired"; fi
now="$(date +%s)"; end="$(date -d "$nextupdate" +%s)"
[ "$end" -gt $((now + 7*86400)) ] || die "CRL expires too soon ($nextupdate) -- regenerate it with refresh-crl.sh"

install -d -m 755 "$CA_TARGET"
install -m 644 "$ca"  "$CA_TARGET/ca.crt"
install -m 644 "$crl" "$CA_TARGET/crl.pem"

$TEST || die "Apache config test failed after install -- NOT reloading"
$RELOAD
echo "Installed. CRL valid until $nextupdate. Apache reloaded."
