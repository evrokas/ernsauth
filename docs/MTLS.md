# Protecting the dashboard with client certificates (mutual TLS)

ErnsAuth's dashboard is the only gate on every SSO login, so it is reachable
only from devices holding a certificate **you** issued. The TLS handshake
fails before any PHP runs, so password guessing, credential stuffing and
bugs in pre-login code are unreachable from the internet.

| Hostname | Serves | Protected by |
|---|---|---|
| `auth.erns.eu` | login, dashboard, `api.php`, `setup.php` | **client certificate**, then password / number matching |
| `sso.erns.eu` | `sso-api.php` only | per-app `X-API-Key`, rate limits, **IP allowlist** |

Both hostnames share one `DocumentRoot` (`web/`); each vhost refuses the
other's files. The API host has no client certificate on purpose: the API key
can't log anyone in by itself (a human still has to approve on the dashboard),
and per-app certificates would cost an extra CA lifecycle for every app.

## What it does and doesn't give you

- Authenticates a **device**, not a person. A stolen unlocked phone, or a
  copied `.p12` plus its password, still gets in -- keep the passcode on, delete
  the `.p12` after installing, revoke on suspicion.
- Not hardware-bound: the key is exportable unless generated on-device (MDM/SCEP,
  out of scope).
- Does not remove handshake-level attacks (Apache/OpenSSL bugs, flooding).

## Which browsers work (tested on a real iPhone)

| Client | Works? |
|---|---|
| Safari on iPhone | **yes** |
| Home-screen web app (Add to Home Screen from Safari) | **yes** |
| Chrome on iPhone | **no** -- iOS Chrome cannot present client certificates; you get `ERR_CONNECTION_CLOSED` |
| Desktop Chrome / Edge | yes, after importing the `.p12` into the OS keychain/store |
| Firefox | yes, after importing into Firefox's own certificate store |

"This site can't be reached / connection closed" on `auth.erns.eu` almost
always means *the browser didn't present a certificate*: open the link in
Safari instead.

## One-time setup

### 1. Create the CA (on your own computer, never on the server)

```bash
deploy/mtls/ca-init.sh        # asks for the CA key passphrase -- put it in your password manager
```

The CA lives in `~/.ernsauth-ca` (override with `ERNSAUTH_CA_DIR`). Back up
`private/ca.key` somewhere offline. Use a CA **dedicated to ErnsAuth** -- never
reuse one from another system.

### 2. Issue a certificate per device

```bash
deploy/mtls/issue-cert.sh evangelos-iphone        # 365 days; prompts for the .p12 export password
deploy/mtls/issue-cert.sh evangelos-laptop --days 180
deploy/mtls/issue-cert.sh evangelos-spare         # keep this one OFFLINE as your second way in
```

`--legacy` re-exports with older algorithms if an Apple device refuses the
import. The `.p12` password is typed on the device; iOS rejects an empty one.
List what exists with `deploy/mtls/list-certs.sh`.

**iPhone:** AirDrop (or iCloud Drive) the `.p12`, tap it, Settings -> *Profile
Downloaded* -> Install (passcode, then the `.p12` password). Then **delete the
`.p12` from every place it was copied.** Never email it.

### 3. Server: DNS, certificates, files

1. DNS: an A/AAAA record for `sso.erns.eu` next to the existing `auth.erns.eu`.
2. The two server certificates must renew over **port 80 with the webroot
   method** -- the HTTPS dashboard now demands a client certificate, so any
   validation that follows a redirect to it would fail:
   ```bash
   sudo mkdir -p /var/www/letsencrypt
   sudo certbot certonly --webroot -w /var/www/letsencrypt -d auth.erns.eu
   sudo certbot certonly --webroot -w /var/www/letsencrypt -d sso.erns.eu
   # an existing auth.erns.eu certificate made with `certbot --apache`:
   #   sudo certbot reconfigure --cert-name auth.erns.eu --authenticator webroot --webroot-path /var/www/letsencrypt
   # and renewals must reload Apache:  --deploy-hook "systemctl reload apache2"
   ```
3. From your computer, copy the public CA certificate and a fresh CRL over, and
   let the server script check and install them:
   ```bash
   deploy/mtls/refresh-crl.sh
   scp ~/.ernsauth-ca/ca.crt ~/.ernsauth-ca/crl.pem you@server:/tmp/
   ssh you@server 'sudo /path/to/ernsauth/deploy/mtls/server-install-crl.sh /tmp/crl.pem /tmp/ca.crt'
   ```
   (The first run reloads Apache before the vhosts exist; that is harmless.)
4. Install the Apache files from `deploy/apache/`, editing the `>>> EDIT <<<`
   lines (document root; the app servers' IPs in `ernsauth-api.conf`):
   ```bash
   sudo a2enmod ssl headers rewrite alias authz_host
   sudo cp deploy/apache/ernsauth-mtls.conf /etc/apache2/ernsauth-mtls.conf
   sudo cp deploy/apache/ernsauth-api.conf deploy/apache/ernsauth-dashboard.conf /etc/apache2/sites-available/
   ```
   Do **not** enable the dashboard yet -- see the cutover order below.
   `000-ernsauth-default.conf` (bare-IP / unknown-hostname catch-all) is
   optional and only safe if ErnsAuth has this Apache to itself; read its header.

### 4. Cutover (in this order, so nothing locks you out)

1. **Open an SSH session and keep it open** until step 5.
2. Enable the API vhost: `sudo a2ensite ernsauth-api && sudo apachectl configtest && sudo systemctl reload apache2`.
   Check from an allowlisted app server: `curl -i https://sso.erns.eu/sso-api.php` -> `401` (no key).
3. In **every app**, change `sso_api_url` to `https://sso.erns.eu/sso-api.php`
   (`config/ernsauth.php`). Verify a real SSO login still works. Apps keep their
   password login as a fallback throughout.
4. Disable the old HTTP-only/certbot site for `auth.erns.eu` (`a2dissite` it and
   its `-le-ssl` copy -- two vhosts for one name conflict), enable
   `ernsauth-dashboard`, `configtest`, reload.
5. On the iPhone, in **Safari**, open `https://auth.erns.eu/` -> choose your
   certificate -> login page. Only then close the SSH session.
6. Health monitoring (see below), then put the CRL reminder in your calendar.

## Everyday operations

### Revoke a device (lost phone, suspected leak)

```bash
deploy/mtls/revoke-cert.sh evangelos-iphone      # also rebuilds the CRL
scp ~/.ernsauth-ca/crl.pem you@server:/tmp/
ssh you@server 'sudo /path/to/ernsauth/deploy/mtls/server-install-crl.sh /tmp/crl.pem'
```

**The revocation is not in force until the new CRL is installed and Apache
reloaded** (Apache reads the CRL only at reload) -- `server-install-crl.sh`
does both and refuses a CRL that isn't signed by your CA or is nearly expired.

### Keep the CRL fresh -- the one thing that can lock you out

An **expired CRL makes Apache refuse every certificate**, including yours. It is
valid 90 days. Put a **recurring calendar reminder every 60 days**: run
`refresh-crl.sh` and install it as above, even if nothing was revoked. The
health check warns 14 days before expiry and fails when it has expired.

### Renew certificates

Device certificates last 365 days. Calendar reminder 30 days before: issue a
new one under a new name (`evangelos-iphone-2027`), install it, then revoke the
old one.

## Recovery

Everything here assumes you can still **SSH to the server**. Keep that working.

| Situation | What to do |
|---|---|
| Browser says "connection closed" | It is not presenting a certificate. Use Safari / the home-screen app; on desktop confirm the `.p12` is in the OS store. |
| CRL expired, every device refused | Over SSH: `refresh-crl.sh` on your computer, `server-install-crl.sh` on the server. If you can't reach your CA computer, use the emergency switch below. |
| Lost phone | `revoke-cert.sh` + install the CRL (above); issue a new certificate for the new phone. |
| Lost every device | Use the offline spare certificate. If it is gone too, emergency switch, then issue new certificates. |
| Lost the CA key or passphrase | Emergency switch, run `ca-init.sh` with a **new** `ERNSAUTH_CA_DIR`, re-issue everything, install the new `ca.crt`/CRL, restore the requirement. |

**Emergency switch** -- over SSH only: in `/etc/apache2/ernsauth-mtls.conf`
change `SSLVerifyClient require` to `SSLVerifyClient none` (and comment out
the two `SSLCARevocation*` lines if the CRL is the problem), then
`sudo apachectl configtest && sudo systemctl reload apache2`. The dashboard is
then protected by password and number matching alone. **Put it back
afterwards.** The health check fails while the requirement is off, so it
can't be forgotten.

## Health monitoring

`deploy/health-handler.php` is unchanged unless these environment variables
are set for the zops run:

| Variable | Meaning |
|---|---|
| `ERNSAUTH_HEALTH_SSO_URL` | the API endpoint to probe, e.g. `https://sso.erns.eu/sso-api.php` (this host must be on the API allowlist) |
| `ERNSAUTH_HEALTH_DASHBOARD_URL` | e.g. `https://auth.erns.eu/` -- turns on the checks below, replacing the old logged-out-dashboard check, which can't run without a certificate |
| `ERNSAUTH_CRL_FILE` | CRL path, default `/etc/ssl/ernsauth-ca/crl.pem` |

With the dashboard URL set it fails if a no-certificate connection is **not**
refused (requirement switched off) and warns/fails on the CRL's age.

## Adding an app whose IP changes

The API allowlist can't hold a moving address. When one appears, either give
that app a stable address (VPN/tunnel to the server) listed in
`ernsauth-api.conf`, or put it on its own hostname that **requires a client
certificate** (a copy of the dashboard vhost serving only `sso-api.php`, and a
`--cert/--key` option added to `ErnsAuthClient`, which has none today). Don't
use `SSLVerifyClient optional` or per-directory requirements: both renegotiate
TLS mid-connection, which is unreliable with TLS 1.3.

## Acceptance tests

Run these after any change to the Apache files, against the real hostnames
(`dev.crt`/`dev.key` = a valid certificate, extracted from a `.p12` with
`openssl pkcs12 -in x.p12 -nodes`):

```bash
curl -sS https://auth.erns.eu/                                         # no certificate -> handshake failure, never a page
curl -sS --cert dev.crt --key dev.key https://auth.erns.eu/login.php  # valid certificate -> login page
curl -sS --cert dev.crt --key dev.key --tls-max 1.2 https://auth.erns.eu/login.php
curl -sS --cert dev.crt --key dev.key https://auth.erns.eu/sso-api.php # -> 403 (API lives on sso.erns.eu)
curl -sSk https://SERVER_IP/                                           # bare IP -> handshake failure (with the catch-all vhost)
curl -sS -o /dev/null -w '%{http_code}\n' http://auth.erns.eu/login.php  # -> 301 only
curl -sS https://sso.erns.eu/login.php                                 # -> 403 (API host serves only sso-api.php)
curl -sS https://sso.erns.eu/sso-api.php                               # from an allowlisted IP -> 401; elsewhere 403
```

Also: a certificate from another CA, an expired one, and a revoked one (before
and after installing the CRL) must all be refused.

These configs and scripts were exercised against a real Apache 2.4.58 +
OpenSSL 3 with 53 checks covering all of the above, the expired-CRL lockout,
the SNI/Host mismatch (`421`), the emergency switch, and argument handling of
every script. That run used test hostnames on high ports; it has **not** been
run on your server or an iPhone against ErnsAuth itself -- do the cutover
steps in order and verify each one.
