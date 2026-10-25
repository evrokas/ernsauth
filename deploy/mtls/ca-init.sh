#!/usr/bin/env bash
# Create the ErnsAuth client-certificate CA. Run once, on your own computer.
#
#   ERNSAUTH_CA_DIR=~/.ernsauth-ca  (default)  where the CA is created
#
# It asks for a passphrase for the CA key. Choose a strong one and keep it
# in your password manager: it is the only thing protecting the key if this
# computer's disk is copied.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$here/common.sh"

[ -e "$CA_DIR/ca.crt" ] && die "a CA already exists in $CA_DIR -- refusing to overwrite it"

umask 077
mkdir -p "$CA_DIR/private" "$CA_DIR/newcerts" "$CA_DIR/issued"
cd "$CA_DIR"
: > index.txt
echo 1000 > serial
echo 1000 > crlnumber

cat > "$CA_CNF" <<CNF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir              = $CA_DIR
database         = \$dir/index.txt
serial           = \$dir/serial
crlnumber        = \$dir/crlnumber
new_certs_dir    = \$dir/newcerts
certificate      = \$dir/ca.crt
private_key      = \$dir/private/ca.key
default_md       = sha256
default_days     = 365
# An EXPIRED CRL makes Apache refuse every certificate (self-lockout), so
# the CRL is valid for 90 days and server-install-crl.sh / the health
# check warn well before then.
default_crl_days = 90
policy           = policy_any
unique_subject   = no

[ policy_any ]
commonName = supplied

[ req ]
distinguished_name = req_dn
prompt             = no

[ req_dn ]
CN = ErnsAuth Client CA

[ ca_ext ]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage         = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash

[ client_ext ]
basicConstraints = CA:FALSE
keyUsage         = critical, digitalSignature
extendedKeyUsage = clientAuth
CNF

# shellcheck disable=SC2046
if [ -n "${ERNSAUTH_CA_PASS:-}" ]; then
    openssl genrsa -aes256 -passout env:ERNSAUTH_CA_PASS -out private/ca.key 4096 2>/dev/null
else
    openssl genrsa -aes256 -out private/ca.key 4096
fi
# shellcheck disable=SC2046
openssl req -x509 -new -key private/ca.key $(ca_passin) -sha256 -days 3650 \
    -config "$CA_CNF" -extensions ca_ext -out ca.crt
chmod 600 private/ca.key

echo
echo "CA created in $CA_DIR"
echo "  ca.crt  -> goes to the server (public, safe to copy)"
echo "  private/ca.key -> NEVER leaves this computer; back it up offline"
openssl x509 -in ca.crt -noout -subject -enddate
echo
echo "Next: issue-cert.sh <name> for each device, then refresh-crl.sh and"
echo "copy ca.crt + crl.pem to the server (see docs/MTLS.md)."
