# Shared by the other scripts in this directory -- sourced, not run.
#
# The CA lives on YOUR OWN COMPUTER (not the web server): the CA key can
# mint a certificate the dashboard will accept, so it must never sit next
# to the thing it protects. Only ca.crt and crl.pem ever go to the server.

CA_DIR="${ERNSAUTH_CA_DIR:-$HOME/.ernsauth-ca}"
CA_CNF="$CA_DIR/openssl.cnf"

die() { echo "error: $*" >&2; exit 1; }

need_ca() {
    [ -f "$CA_DIR/ca.crt" ] && [ -f "$CA_DIR/private/ca.key" ] \
        || die "no CA in $CA_DIR -- run ca-init.sh first (or set ERNSAUTH_CA_DIR)"
}

# ERNSAUTH_CA_PASS is a convenience for automated tests only; interactively
# openssl prompts for the CA key passphrase, which is what you want.
ca_passin() {
    if [ -n "${ERNSAUTH_CA_PASS:-}" ]; then
        echo "-passin" "env:ERNSAUTH_CA_PASS"
    fi
}
