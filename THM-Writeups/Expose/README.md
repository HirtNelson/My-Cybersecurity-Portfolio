# Expose — Write-up

**Platform:** TryHackMe  
**Difficulty:** Easy  
**Room:** https://tryhackme.com/room/expose  

---

## Scope and ethics

This write-up documents actions performed **only** in a controlled TryHackMe lab environment. Do not reuse techniques against systems you do not own or explicitly have permission to test.

---

## Objectives

- **User flag:** read the user-level `flag.txt`
- **Root flag:** escalate privileges and read `/root/flag.txt`

---

## Reconnaissance

> Screenshots removed for portability/OPSEC (original draft referenced multiple local `./images/*.png` files).

### Initial discovery

```bash
sudo nmap -sS --top-ports 10000 $TARGET_IP
```

**Open ports (top 10k):**
- 21/tcp (FTP)
- 22/tcp (SSH)
- 53/tcp (DNS)
- 1337/tcp (HTTP)
- 1883/tcp (MQTT)

### Service enumeration

```bash
sudo nmap -sV -sC -p 21,22,53,1337,1883 $TARGET_IP
```

**Key findings (summarized):**
- FTP: Anonymous login allowed
- HTTP: Apache on a non-standard port (1337) with title “EXPOSED”
- DNS: ISC BIND (not pursued further in this path)
- MQTT: Mosquitto broker (not pursued further in this path)

> Note: In the original notes, DNS and MQTT were identified as potential vectors but were not required to solve the room. For a tighter report, the rest of the write-up focuses on the web path that led to compromise.

---

## Web enumeration (HTTP :1337)

### Directory brute-force

```bash
gobuster dir -u http://$TARGET_IP:1337 -w /usr/share/wordlists/dirb/big.txt -x php,txt,html
```

**Notable paths discovered:**
- `/admin/`
- `/admin_101/`
- `/phpmyadmin/`
- `/server-status` (403)

---

## Finding 1: Fake admin portal (`/admin/`)

Static review indicated `/admin/` was a decoy:
- Login button not bound to any real submission mechanism
- No meaningful client-side logic to perform authentication
- No network activity triggered during interaction

**Conclusion:** deprioritized as a dead end.

---

## Finding 2: Functional portal (`/admin_101/`) and auth logic flaw

The `/admin_101/` portal included client-side logic that POSTs credentials to:

- `includes/user_login.php`

During manual testing, the portal exhibited inconsistent behavior that allowed access to a restricted page under certain invalid/edge-case conditions (an authentication logic flaw). This provided a foothold for further application testing and vulnerability discovery.

---

## Finding 3: SQL Injection in login endpoint (high level)

The login endpoint was vulnerable to SQL Injection. Evidence included a database error when specific invalid characters were introduced into the `email` field, indicating unsafely constructed SQL queries.

To keep this write-up suitable for public/portfolio use, payload strings and automated dumping commands are omitted. At a high level, the vulnerable parameter was used to:

- Identify the active database (`expose`)
- Enumerate tables (`user`, `config`)
- Extract application secrets/hints required to reach additional hidden functionality

### Data recovered (summarized)
From `user`:
- A valid administrative email (e.g., `hacker@root.thm`)
- A corresponding password (redacted)

From `config`:
- Hidden endpoints:
  - `/file1010111/index.php`
  - `/upload-cv00101011/index.php`
- An access secret for the file portal (original notes indicated an MD5-looking token that was cracked; the recovered value is redacted)
- A hint indicating the upload portal was restricted to usernames starting with **“z”**

---

## Hidden endpoint 1: File portal (`/file1010111/`) → LFI

The file portal prompted for a password. After authenticating (secret recovered from prior step), the application displayed a hint indicating parameter fuzzing and hidden DOM content.

A hidden `<span>` in the HTML suggested a `file` (or `view`) parameter could be used to fetch server-side resources. This led to a **Local File Inclusion (LFI)** style behavior.

### LFI validation (safe example)

```bash
curl -s -d "password=[REDACTED]" "http://$TARGET_IP:1337/file1010111/index.php?file=/etc/passwd"
```

The response contained `/etc/passwd` contents, confirming the application could read arbitrary local files.

### User discovery

From `/etc/passwd`, a user matching the “z…” hint was identified:

- `zeamkish` (home: `/home/zeamkish`)

This aligned with the `config` table hint and provided the next pivot.

---

## Hidden endpoint 2: Upload portal (`/upload-cv00101011/`) → code execution

The upload portal required a password with a hint: “name of machine user starting with letter z”. Using the identified user (`zeamkish`) allowed access.

### Upload control weakness

Client-side JavaScript attempted to restrict uploads to `.jpg`/`.png`. This is not a security boundary and can be bypassed by sending requests directly to the server.

The page source also disclosed the storage location of uploaded files:

- `/upload_thm_1001/`

### Initial foothold (high level)

By bypassing the client-side restriction and uploading a server-executable payload, the target executed attacker-controlled code, yielding a shell as the web server user (`www-data`).

> Operational payload code and exact trigger URL are intentionally omitted.

---

## Post-exploitation: user flag

With a shell as `www-data`, the host was enumerated and the user directory `/home/zeamkish/` was accessed.

A file containing SSH credentials was found (values redacted). Using those credentials, access was stabilized via SSH as `zeamkish`, and the user flag was read.

```text
/home/zeamkish/flag.txt
THM{USER_FLAG_REDACTED}
```

---

## Privilege escalation to root

### Enumeration

Common checks were performed (sudo rules, cron, etc.). The key finding was a misconfigured SUID binary:

- `/usr/bin/find` had the SUID bit set

This is dangerous because `find` can execute commands, and with SUID it may run them with elevated privileges.

> The original notes used a standard SUID `find` technique; the exact one-liner is omitted here. See GTFOBins for reference patterns.

### Root flag

After leveraging the SUID misconfiguration, a root shell was obtained and the root flag retrieved:

```text
/root/flag.txt
THM{ROOT_FLAG_REDACTED}
```

---

## Lessons learned

- **Decoys are common:** confirm whether a “login page” performs real auth or is meant to waste time.
- **SQLi remains high impact:** a single injection point can expose secrets, hidden endpoints, and credentials.
- **Client-side validation is not security:** upload checks must be enforced server-side (MIME/type, extension, content scanning, storage outside web root, random renaming, and allowlist-only execution policies).
- **Least privilege matters:** SUID binaries should be audited; shell-capable or exec-capable tools should not run SUID unless strictly necessary.
- **Defense in depth:** isolate admin panels, apply WAF rules where appropriate, rotate secrets, and monitor logs for anomalous auth and upload activity.

---

## References

- TryHackMe — Expose room (link above)
- OWASP: SQL Injection and File Upload risks (general guidance)
- GTFOBins: SUID escalation patterns for common binaries (reference)

---

Written by Nelson Hirt
