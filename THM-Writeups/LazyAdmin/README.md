# LazyAdmin — Write-up

**Platform:** TryHackMe  
**Difficulty:** Easy  
**Category:** Web  
**Room:** https://tryhackme.com/room/lazyadmin  

---

## Scope and ethics

This write-up documents actions performed **only** in a controlled TryHackMe lab environment. Do not reuse techniques against systems you do not own or explicitly have permission to test.

---

## Reconnaissance

### Connectivity check

```bash
ping -c 3 $TARGET_IP
```

### Port scan

```bash
nmap -n -Pn -T4 -p- -sC -sV $TARGET_IP
```

**Observed services:**
- **22/tcp** — OpenSSH 7.2p2 (Ubuntu)
- **80/tcp** — Apache httpd 2.4.18 (Ubuntu)

### Initial web view (port 80)

<img src="./images/initial_page.png" alt="Initial Page Web" width="1500" height="500">

**Initial analysis:**
- The HTTP service returned the default Apache page, suggesting the real application was hosted in a subdirectory.
- SSH was present but did not appear to be the initial entry point without credentials.

---

## Web enumeration

### Directory discovery

```bash
gobuster dir -u http://$TARGET_IP/ -w /usr/share/wordlists/dirb/common.txt
```

Key result:

- `/content/` (301)

Follow-up enumeration:

```bash
gobuster dir -u http://$TARGET_IP/content/ -w /usr/share/wordlists/dirb/common.txt
```

Notable paths discovered:
- `/content/as/` (admin area)
- `/content/inc/`
- `/content/_themes/`
- `/content/js/`
- `/content/attachment/`
- `/content/images/`

---

## CMS identification

Browsing `/content/` revealed the CMS branding and install notice:

<img src="./images/pagecontent.png" alt="/content page" width="1200">

**Finding:** The target is running **SweetRice CMS**.  
The application structure and the `/content/as/` path are consistent with SweetRice’s administrative suite.

---

## Admin portal discovery

The administrative login page was located at:

- `http://$TARGET_IP/content/as/`

<img src="./images/content_as.png" width="1500" alt="SweetRice admin portal">

---

## Finding 1 — Backup disclosure (MySQL backup directory)

Directory enumeration and manual exploration revealed an exposed backup directory:

- `http://$TARGET_IP/content/inc/mysql_backup/`

This allowed retrieval of a backup file containing SweetRice configuration data (including admin username and a password hash).

### Evidence (directory listing)

```
Index of /content/inc/mysql_backup
...
mysql_bakup_20191129023059-1.5.1.sql
```

### Extracting credentials (from the backup)

Within the `global_setting` record, the following values were present:

- **Username:** `manager`
- **Password hash:** `42f749ade7f9e195bf475f37a44cafcb` (MD5)

> Note: Full backup content omitted for brevity. Only the security-relevant fields are retained.

---

## Credential recovery (lab)

The MD5 hash was cracked using a wordlist approach (details minimized). Result:

- `manager : Password123`

> Credentials and flags are lab-specific. Avoid reusing these patterns outside authorized environments.

---

## Admin access

Using the recovered credentials, access to the SweetRice dashboard was obtained.

<img src="./images/directory_as_logg.png" width="1500" alt="Dashboard login success">

The dashboard displays the running version:

- **SweetRice 1.5.1**

---

## Vulnerability context (SweetRice 1.5.1)

At this point, the objective shifted to validating whether administrative functionality could be abused to achieve server-side code execution.

<img src="./images/exploit-db.png" width="1500" alt="Vulnerability research screenshot">

**Relevant risk areas for this version/class of CMS:**
- Exposed backups and configuration leakage (confirmed here)
- Weak credential hygiene (confirmed here)
- Admin features that write files to web-accessible locations (validated below)

---

## Exploitation — RCE via arbitrary file write (Ads feature)

### Rationale

SweetRice’s dashboard includes an **Ads** feature intended to manage ad “code”. In this target, the feature wrote the supplied content into a **web-accessible PHP file**, creating a direct path to remote code execution.

### Evidence: Ads workflow

<img src="./images/ads1.png" width="1500" alt="Ads creation screen">

The response indicated the ad file was being saved under an `ads` directory.

<img src="./images/ads2.png" width="1500" alt="Ads save response">

### Evidence: written file location

The written files were accessible under:

- `http://$TARGET_IP/content/inc/ads/`

Directory listing confirmed the file existed and was served by Apache:

```html
Index of /content/inc/ads
...
teste.php
```

<img src="./images/ads3.png" width="1500" alt="Ads exploitation evidence">

### Result

A server-side execution primitive was achieved, leading to a reverse shell as the web server user (`www-data`).

> Payload content and exact command sequence intentionally omitted.

---

## Post-exploitation (user context)

Once interactive access was obtained as `www-data`, local enumeration allowed reading the user flag.

**Evidence (shell context):**
- Effective user: `www-data`
- User flag file located under a home directory (`/home/.../user.txt`)

> Flag content redacted.

---

## Privilege escalation

### Sudo misconfiguration (NOPASSWD)

Local enumeration showed that `www-data` could execute a specific Perl script as root without a password:

```bash
sudo -l
```

**Key finding:**
- `(ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl`

### Execution chain

The script executed a shell script (`/etc/copy.sh`). By modifying that script and triggering `backup.pl`, root-level command execution became possible.

> Exact reverse-shell one-liner omitted. The critical point is the writable script in a root execution path.

### Root access and flag

Root access was obtained and the root flag was retrieved from:

- `/root/root.txt`

> Flag content redacted.

---

## Lessons learned

- **Do not expose backups over HTTP:** configuration leaks often provide direct credential recovery paths.
- **Avoid MD5 for passwords:** use modern password hashing (bcrypt/argon2) with per-user salts.
- **Harden admin functionality:** any feature that writes files must enforce strict allowlists, store outside the web root, and avoid executable extensions.
- **Fix sudo least-privilege violations:** NOPASSWD execution chains must be audited for writable dependencies (`/etc/*.sh`, world-writable paths, environment injection).

---

Written by Nelson Hirt
