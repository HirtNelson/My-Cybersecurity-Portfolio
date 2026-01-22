# Hammer — Write-up

**Platform:** TryHackMe  
**Difficulty:** Medium  
**Category:** Web  
**Room:** https://tryhackme.com/room/hammer  

---

## Scope and ethics

This write-up documents actions performed **only** in a controlled TryHackMe lab environment. Do not reuse techniques against systems you do not own or explicitly have permission to test.

---

## Objectives

- **Challenge 1:** Obtain the flag shown immediately after a successful login to the control panel.
- **Challenge 2:** Read the protected file at `/home/ubuntu/flag.txt` (RCE path).

---

## Setup

> The room expects hostname-based access. Map the target IP locally so scripts and links resolve correctly.

```bash
echo "$TARGET_IP hammer.thm" | sudo tee -a /etc/hosts
```

---

## Reconnaissance

### Connectivity

```bash
ping -c 3 hammer.thm
```

### Port scanning

```bash
sudo nmap -Pn -n -sS --top-ports 10000 --min-rate 1000 $TARGET_IP
```

**Observed open ports:**
- 22/tcp (SSH)
- 1337/tcp (HTTP)

### Web fingerprinting

```bash
whatweb http://hammer.thm:1337
```

**High-level summary:**
- Apache 2.4.41 (Ubuntu)
- PHP session cookie present (`PHPSESSID`)
- Bootstrap/HTML5 login page

---

## Web enumeration (HTTP :1337)

### Login entry point (evidence)

<div align="center">
  <img src="./images/login.png" width="1000" alt="Login Form Details">
  <br>
  <em>Figure: Authentication entry point on port 1337.</em>
</div>

### Source review (login page)

Notable developer note in the HTML hinted at a directory naming convention:

- `hmr_DIRECTORY_NAME`

This was used to guide directory discovery.

### Directory fuzzing (based on `hmr_` prefix)

```bash
ffuf -u http://hammer.thm:1337/hmr_FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302
```

**Discovered directories (summary):**
- `/hmr_css/`
- `/hmr_images/`
- `/hmr_js/`
- `/hmr_logs/`

---

## Finding 1: Log exposure (`/hmr_logs/`)

The application logs were directly accessible from the web server:

- `/hmr_logs/error.logs`

**Security impact:**
- Information disclosure (internal paths and auth-related messages)
- Leakage of a valid user identifier (`tester@hammer.thm`)
- Evidence of attempted access to sensitive locations (e.g., `/etc/shadow`), indicating poor log hygiene and excessive detail exposure

---

## Finding 2: Authentication workflow and password reset attack surface

The login page returned generic errors for invalid credentials (good practice against basic enumeration), so the password reset flow became the primary enumeration and bypass target.

<div align="center">
  <img src="./images/reset_page.png" width="1000" alt="Reset Password Page">
  <br>
  <em>Figure: Password recovery interface.</em>
</div>

### Reset page source review (corrected excerpt)

In the original notes, one snippet contained an invalid line (`let countdownv = ;`). The relevant/functional logic is represented below:

```html
<script>
let countdownv = 180;
function startCountdown() {
  const hiddenField = document.getElementById("s");
  setInterval(function() {
    countdownv--;
    hiddenField.value = countdownv;
    if (countdownv <= 0) window.location.href = 'logout.php';
  }, 1000);
}
</script>
```

**Key observation (risk):**
- A hidden input (`name="s"`) is updated client-side and submitted with the recovery flow.
- If the server trusts this value for time-window validation, the client can manipulate it.

---

## Exploitation (high level)

To keep this write-up suitable for public/portfolio use, operational exploit scripts, brute-force code, full tokens, and step-by-step weaponization details are omitted.

### Step 1 — User confirmation via password reset behavior

Using the leaked account (`tester@hammer.thm`), the reset flow produced a distinct server behavior consistent with “email exists” (e.g., redirect/flow continuation). This confirmed the account was valid.

### Step 2 — Rate limiting weakness (session-bound)

Observed behavior indicated the “Rate-Limit-Pending” control was tied to the **session cookie** (`PHPSESSID`) rather than the account itself. Rotating sessions reset the attempt counter.

**Impact:** enables high-volume attempts across multiple sessions.

### Step 3 — Time-window weakness (client-controlled)

The reset workflow included the `s` parameter (derived from the client-side countdown). By holding this value at a “valid” number, the attacker could avoid expiry in repeated submissions if the backend validated based on `s`.

**Impact:** extends the effective brute-force window.

### Step 4 — Recovery code discovery → authenticated session

By combining:
- session rotation (to reset attempt counters), and
- time-window manipulation (to bypass expiry),

the reset workflow could be abused to reach an authenticated state. A validated session cookie was then used to access the control panel.

<div align="center">
  <img src="./images/image-9.png" width="1000" alt="Code and Session Discovery">
  <br>
  <em>Figure: Evidence of recovery flow success (code/cookie captured in the lab).</em>
</div>

<div align="center">
  <img src="./images/image-11.png" width="1000" alt="Successful Login Bypass">
  <br>
  <em>Figure: Control panel access after session injection (lab environment).</em>
</div>

### Challenge 1 — Control panel flag

The first flag was displayed immediately after a successful login.

> Flag value redacted: `THM{FLAG_REDACTED}`

<div align="center">
  <img src="./images/image-12.png" width="1000" alt="Dashboard and Flag Capture">
  <br>
  <em>Figure: Dashboard displaying the first flag (redacted).</em>
</div>

---

## Post-auth findings: command execution surface and JWT exposure

After authentication bypass, the dashboard source showed a command execution feature and a JWT being used for API authorization.

### Observations (high level)

- **Command execution endpoint** exposed (e.g., `execute_command.php`) receiving JSON like `{ "command": "..." }`
- **JWT present client-side** (hardcoded in the page), implying token leakage
- **Client-side “persistence” checks** (cookie-based checks enforced in JavaScript)

> Full JWT string removed. Only the security-relevant fields are discussed below.

### JWT risk indicators

- `alg`: HS256 (symmetric)  
- `kid`: pointed to a local key path (e.g., `/var/www/...key`)

**Security implication:**
- If an attacker can read the signing key (directly or indirectly), they can forge higher-privilege JWTs.

<div align="center">
  <img src="./images/image-13.png" width="1000" alt="JWT Decoding Analysis">
  <br>
  <em>Figure: JWT decoding view (token redacted).</em>
</div>

---

## Challenge 2 — RCE path to `/home/ubuntu/flag.txt` (high level)

Even limited command execution is enough to enumerate the web root and locate sensitive files referenced by the application.

### Key pivot (summarized)

- Use the command interface to enumerate server directories and locate the JWT signing key file referenced by `kid`.
- Exfiltrate the signing key (in this lab, a short secret string).
- Forge a JWT with elevated role claims (e.g., `role=admin`) using HS256 and the recovered key.
- Use the forged token to access higher-privilege command execution and read the protected file.

> Exfiltrated key and the full forgery script are omitted. Screenshots retained.

<div align="center">
  <img src="./images/image-17.png" width="1000" alt="JWT Forgery with Exfiltrated Key">
  <br>
  <em>Figure: Forging a higher-privilege JWT using the recovered signing key (details redacted).</em>
</div>

### Protected file content

> Content redacted: `/home/ubuntu/flag.txt` → `THM{FLAG_REDACTED}`

<div align="center">
  <img src="./images/image-19.png" width="1000" alt="Final Flag Captured">
  <br>
  <em>Figure: Final flag capture (redacted).</em>
</div>

---

## Lessons learned

- **Do not expose logs over HTTP:** logs can leak valid users, internal paths, and sensitive operational detail.
- **Rate limiting must be account- and IP-aware:** session-bound throttling is trivial to bypass.
- **Client-side timers are not controls:** enforce expiry server-side (signed state, server timestamps).
- **Never embed secrets in client code:** hardcoded JWTs collapse the auth model.
- **Protect signing keys:** store outside web-accessible paths; use least-privilege file permissions; rotate on suspicion.
- **RCE + key leakage ⇒ full compromise:** once the signing key is disclosed, privilege boundaries disappear.

---

## References

- OWASP: Authentication, session management, and brute-force protections
- OWASP: Sensitive data exposure / security logging guidance
- JWT best practices (HS256 key management, `kid` handling, and signing key storage)

---

Written by Nelson Hirt
