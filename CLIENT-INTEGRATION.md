# Integrating an app with ErnsAuth

How a client app signs its users in through ErnsAuth. There are two flows, and
the choice between them is about **whether your app asks the user who they
are** before authenticating:

| | **A. Number matching** | **B. Email OTP** |
|---|---|---|
| User types, to start | nothing | their email address |
| Where they confirm | the ErnsAuth dashboard, in another tab or on their phone | their inbox |
| They must already be signed in to ErnsAuth | **yes** — to approve, they need a dashboard session | no |
| Needs SMTP configured on the ErnsAuth server | no | **yes** |
| Who ends up signed in | whichever ErnsAuth user approves the number | only the owner of that mailbox |
| API calls | 3 (`create_challenge` → `poll_challenge` → `exchange_code`) | 2 (`send_otp` → `verify_otp`) |

Flow **A** suits an app one person (or a small, trusted group) uses from a
device where the ErnsAuth dashboard is already open — it's the fastest to use
and has no mail dependency. Flow **B** suits an app whose users aren't
necessarily signed in to ErnsAuth already, or who reach it from a device where
opening the dashboard is inconvenient.

Both flows end the same way: ErnsAuth hands you `user_id`, `username`, `email`
and `display_name`, and **your app** creates its own session from that.

> **On "username":** the OTP flow identifies the user by **email address**
> — `send_otp` validates the field with `FILTER_VALIDATE_EMAIL` and looks the
> account up by email only. ErnsAuth accounts *do* have a separate username,
> but it comes back in the response rather than being accepted as input. If you
> want users to type a username, map it to an email in your own app first.

---

## Before you start

### 1. Register the app

In the ErnsAuth dashboard: **Admin → Client Apps → Add App**. You get an API
key **shown once, at creation** — copy it then. (Lost it? Edit the app and use
*Regenerate API Key*; the old key stops working immediately.)

### 2. Vendor the client library

Clone the `stable` branch into your app rather than hand-copying
`client/ErnsAuthClient.php`, so `git pull` picks up fixes instead of silently
drifting:

```bash
git clone -b stable https://github.com/evrokas/ernsauth.git lib/ernsauth
```

Put it **outside your web root** (or otherwise unreachable over HTTP), and
gitignore it. `client/VersionCheck.php` can tell you when your clone is behind
`stable` — see the README.

### 3. Store the connection details outside the web root

```php
// config/ernsauth.php  — gitignored, NOT under your DocumentRoot
return [
    'sso_api_url' => 'https://auth.example.com/sso-api.php',
    'api_key'     => '...',   // the key from step 1
];
```

The API key authenticates **your app**, not your user. Treat it like a database
password: anyone holding it can create and poll challenges as your app.

```php
require_once __DIR__ . '/lib/ernsauth/client/ErnsAuthClient.php';

$cfg    = require __DIR__ . '/config/ernsauth.php';
$client = new ErnsAuthClient($cfg['sso_api_url'], $cfg['api_key']);
```

Every `ErnsAuthClient` method **throws `RuntimeException`** on a transport
error, malformed JSON, or any HTTP status ≥ 400. Wrap calls in `try/catch` —
the sections below assume you do.

---

## Flow A — number matching (no username)

Your app asks for nothing. It requests a challenge, shows the user a two-digit
number, and waits. The user opens their ErnsAuth dashboard, sees a pending
login from your app, and picks that number out of a set of decoys. Picking the
right one approves it.

```
   your app                     ErnsAuth                    the user
      │                            │                            │
      │  POST create_challenge     │                            │
      ├───────────────────────────>│                            │
      │  {challenge_id, number}    │                            │
      │<───────────────────────────┤                            │
      │                                                         │
      │  show the number ───────────────────────────────────────>│
      │                            │   approves it in the       │
      │                            │<── dashboard (picks the ───┤
      │  GET poll_challenge        │    number among decoys)    │
      ├───────────────────────────>│                            │
      │  {status: approved,        │                            │
      │   auth_code}               │                            │
      │<───────────────────────────┤                            │
      │  POST exchange_code        │                            │
      ├───────────────────────────>│                            │
      │  {user_id, username, ...}  │                            │
      │<───────────────────────────┤                            │
```

### 1. Create the challenge — only on an explicit user action

```php
$challenge = $client->createChallenge(
    $_SERVER['REMOTE_ADDR']    ?? '',   // the END USER's IP
    $_SERVER['HTTP_USER_AGENT'] ?? ''   // the END USER's browser
);
// => ['challenge_id' => '…32 hex…', 'challenge_number' => 47,
//     'expires_at' => 1788261666, 'superseded_count' => 0]

$_SESSION['ea_pending_challenge'] = [
    'id'         => $challenge['challenge_id'],
    'number'     => $challenge['challenge_number'],
    'expires_at' => $challenge['expires_at'],
];
```

Three things matter here:

**Pass the end user's IP and User-Agent, not your server's.** They're optional
in the API, but if you omit them ErnsAuth falls back to the IP of *your server*
(the caller it sees) and an empty UA. That breaks two things: the approver sees
the wrong device in their pending list, and — because superseding (below)
matches on `(app, IP, user agent)` — every user of your app lands in one bucket
and they start cancelling each other's pending logins.

**Do not create a challenge on page load.** Put it behind a button ("Sign in
with ErnsAuth"). Every challenge is a live row in the approver's *Pending
Logins* list until it expires (`challenge_ttl`, 5 min by default), so a bookmark
hit, a prefetch, or a crawler would otherwise post a login request nobody made.

**`superseded_count` tells you what this call cleaned up.** Creating a challenge
automatically expires any still-pending challenge from the same app + IP + user
agent, so a reload or a "try again" never leaves a stale number sitting in the
approver's list next to the live one. You can ignore the field; it's there for
logging.

### 2. Show the number and poll

Show `challenge_number` and poll from the browser against **your own**
endpoint, which forwards to ErnsAuth server-side (keeping the API key on the
server):

```php
// e.g. login.php?action=poll  — returns JSON to your page's fetch() loop
$pending = $_SESSION['ea_pending_challenge'] ?? null;
if (!$pending) { echo json_encode(['status' => 'not_found']); exit; }

$poll = $client->pollChallenge($pending['id']);
```

`$poll['status']` is one of:

| status | meaning | what to do |
|---|---|---|
| `pending` | not answered yet | poll again in ~2s |
| `approved` | approved; `$poll['auth_code']` is set | exchange it (step 3) |
| `rejected` | the user declined it | stop; offer a fresh request |
| `expired` | passed `challenge_ttl` unanswered | stop; offer a fresh request |
| `not_found` | unknown id, or it belongs to another app | stop; offer a fresh request |

A 2-second interval is the right ballpark: polling is limited to
`rate_challenge × 10` (300 per 300s by default) per IP, so ~1 poll/sec
sustained is the ceiling and 2s leaves comfortable headroom. Stop the loop on
every terminal status — don't keep hammering a `rejected` challenge.

### 3. Exchange the auth code

```php
if ($poll['status'] === 'approved' && !empty($poll['auth_code'])) {
    $user = $client->exchangeCode($poll['auth_code']);
    // => ['user_id' => …, 'username' => …, 'email' => …, 'display_name' => …]

    session_regenerate_id(true);
    $_SESSION['authed'] = true;
    $_SESSION['user']   = $user;
    unset($_SESSION['ea_pending_challenge']);
}
```

The auth code is **single use** — a second exchange of the same code fails,
by design (it's row-locked server-side, so two racing requests can't both
succeed). Exchange it as soon as polling reports `approved`.

Mind the deadline: it's measured from when the **challenge** was created, not
from when the user approved it — `created_at + challenge_ttl + auth_code_ttl`,
so 360s after creation with the defaults. A user who approves at the 5-minute
mark leaves you seconds, not a fresh minute.

### 4. Give the user a way out

Losing sync is the common failure here: the number on screen no longer matches
anything the approver can see (a stale tab, a challenge that quietly expired,
two tabs racing). Polling can't detect that — the challenge is perfectly valid,
it's just not the one being looked at. So always show a **"new request"**
control alongside the number, live at all times rather than only after an
error. Clicking it just runs step 1 again, which supersedes the old challenge
as a side effect.

`web/login.php` in [apyweb](https://github.com/evrokas/apyweb) is a complete
working implementation of this flow — explicit start button, session-stored
challenge, poll endpoint, and recovery link.

---

## Flow B — email OTP (user identifies first)

Your app asks for an email address, ErnsAuth mails a 6-digit code, your app
verifies it. No dashboard visit, no approval step.

```php
// Step 1 — the user submitted their email
$otp = $client->sendOtp($email);
$_SESSION['ea_otp_id'] = $otp['otp_id'];
// then: show a "we sent you a code" form
```

```php
// Step 2 — the user submitted the 6-digit code
$user = $client->verifyOtp($_SESSION['ea_otp_id'], $code);
// => ['user_id' => …, 'username' => …, 'email' => …, 'display_name' => …]

session_regenerate_id(true);
$_SESSION['authed'] = true;
$_SESSION['user']   = $user;
unset($_SESSION['ea_otp_id']);
```

Four behaviours to build around:

**A successful `send_otp` proves nothing.** It returns an `otp_id` even when
the email belongs to no account, or to a deactivated one — deliberately, so
your login form can't be used to enumerate who has an account. Always advance
to the code screen and let `verify_otp` be the thing that fails. Never branch
on `send_otp` to tell the user "no such account".

**It also returns success when the mail could not be sent.** If the ErnsAuth
server has no SMTP configured, or PHPMailer is missing, the failure is written
to the server's error log and `send_otp` still returns an `otp_id`. From your
side it's indistinguishable from a delivered code — the user just never gets an
email. Confirm SMTP works on the ErnsAuth server before shipping this flow, and
when a user reports "no code arrived", check the ErnsAuth error log first.

**A wrong code does not burn the `otp_id`.** Only a correct code marks it used,
so let the user retry a typo against the same `otp_id` until `otp_ttl`
(10 minutes) runs out. `rate_otp_verify` (5 attempts / 15 min per IP) is what
bounds guessing — a 6-digit code needs that limit to be meaningful, so don't
build a retry loop that works around it.

**Login codes and reset codes aren't interchangeable.** `verify_otp` only
accepts codes issued for the `login` purpose; a password-reset code won't work,
and vice versa.

`request_password_reset` / `verify_password_reset` exist on the same client for
password changes. They're a separate flow, not part of signing in.

---

## After either flow: your app's own session

ErnsAuth authenticates the user and hands you their identity. It does **not**
manage your app's session — the `ea_session` cookie belongs to the ErnsAuth
dashboard, on the ErnsAuth domain, and your app neither sees nor uses it.
Signing out of your app doesn't sign them out of ErnsAuth, and vice versa.

So on success:

```php
session_regenerate_id(true);     // fresh id — don't reuse the pre-login one
$_SESSION['authed'] = true;
$_SESSION['user']   = $user;     // user_id / username / email / display_name
```

and set your session cookie the way you'd set any other:

```php
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => true,          // behind a proxy, check X-Forwarded-Proto
    'httponly' => true,
    'samesite' => 'Strict',
]);
```

**There is no per-user allowlist.** Anyone with an active ErnsAuth account who
completes either flow is authenticated to your app. If only certain people
should get in, check the returned `user_id` or `username` against your own list
before granting the session — ErnsAuth won't do it for you.

---

## Errors and rate limits

`ErnsAuthClient` throws `RuntimeException` for all of these; the message
carries the server's text.

| HTTP | When |
|---|---|
| 400 | bad or missing input, invalid/expired code, expired auth code |
| 401 | `X-API-Key` missing, or not a registered/active app |
| 405 | wrong method for the action (`create_challenge` is POST, `poll_challenge` is GET) |
| 429 | rate limited |
| 503 | ErnsAuth can't reach its own database |

Defaults, per IP unless noted — all of them are tunable by an admin at
**Admin → Rate Limits** without a redeploy, so treat these as starting points
rather than constants:

| Action | Limit | Keyed on |
|---|---|---|
| `create_challenge` | 30 / 5 min | app + IP |
| `poll_challenge` | 300 / 5 min | IP |
| `exchange_code` | 20 / 5 min | app + IP |
| `send_otp` | 3 / 15 min | IP |
| `verify_otp` | 5 / 15 min | IP (reset on success) |

Handle 429 by telling the user to wait, not by retrying in a tighter loop.

---

## Branding the sign-in screen (optional)

If your app names ErnsAuth anywhere in its own UI — a subtitle, a button
label, an "update available" banner — write it as **ERNSAuth**, and
anywhere that text isn't sitting on a solid-color background, color the
"Auth" half `#5b7cf6`: the same blue ErnsAuth's own logo uses for that half
of its name (`web/css/auth.css` and `web/css/dashboard.css` in this repo,
`h1 span { color: #5b7cf6; }`). It reads as the same mark rather than a
random blue.

```html
<div class="subtitle">Sign in via ERNS<span style="color:#5b7cf6">Auth</span></div>
```

Skip the color on a button whose own background is already blue — a light
blue on a darker blue fill hurts contrast rather than reading as the brand,
so plain white (or whatever the button's normal text color is) is the right
call there:

```html
<a class="start-btn" href="login.php?start=1">Sign in with ERNSAuth</a>
```

Plain-text output — a `die()` message, a JSON error string — has no markup
to color at all, so it just gets the plain "ERNSAuth" spelling and nothing
else.

`web/login.php` and the update-notice banner in
[apyweb](https://github.com/evrokas/apyweb)'s `web/index.php` do exactly
this and are the reference.

---

## Checklist

- [ ] App registered; API key stored outside the web root and gitignored
- [ ] `lib/ernsauth` cloned from `stable`, outside the web root
- [ ] Every client call wrapped in `try/catch` for `RuntimeException`
- [ ] **Flow A:** challenge created only on an explicit click, never on page load
- [ ] **Flow A:** end user's real IP and User-Agent passed to `createChallenge`
- [ ] **Flow A:** `challenge_id` kept server-side, in the session
- [ ] **Flow A:** polling stops on `approved` / `rejected` / `expired` / `not_found`
- [ ] **Flow A:** a "new request" control visible at all times, not only after an error
- [ ] **Flow B:** SMTP verified working on the ErnsAuth server
- [ ] **Flow B:** no branching on `send_otp` — it succeeds for unknown emails too
- [ ] **Flow B:** retries allowed against the same `otp_id`
- [ ] `session_regenerate_id(true)` on success
- [ ] Per-user authorization applied in your app, if you need it
- [ ] (optional) Sign-in UI names it "ERNSAuth", with "Auth" colored `#5b7cf6` off a solid-blue background
