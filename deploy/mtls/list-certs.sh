#!/usr/bin/env bash
# List every certificate this CA has issued: status, expiry, serial, name.
#
#   list-certs.sh
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
. "$here/common.sh"
need_ca

printf '%-8s %-12s %-8s %s\n' STATUS EXPIRES SERIAL NAME
# Expiry is YYMMDDHHMMSSZ in index.txt.
awk -F'\t' '{
    st = ($1=="V") ? "valid" : ($1=="R") ? "REVOKED" : "expired";
    e = $2; expires = "20" substr(e,1,2) "-" substr(e,3,2) "-" substr(e,5,2);
    name = $6; sub(/^\/CN=/, "", name);
    printf "%-8s %-12s %-8s %s\n", st, expires, $4, name
}' "$CA_DIR/index.txt"
