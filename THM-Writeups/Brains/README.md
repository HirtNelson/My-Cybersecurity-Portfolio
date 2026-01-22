# Brains — Write-up
*The city forgot to close its gate.*

**Difficulty:** Easy  
**Platform:** TryHackMe  
**Room:** https://tryhackme.com/room/brains  

---

## Scope and ethics

This write-up describes actions performed **only** in a controlled TryHackMe lab environment. Do not reuse techniques against systems you do not own or explicitly have permission to test.

---

## Objective

**Task 1 (Red Team):** Retrieve the content of `flag.txt` from the user’s home directory.  
**Task 2 (Blue Team):** Use Splunk to investigate artifacts left by the compromise.

---

## Task 1 — Red Team: Exploit the Server

### Reconnaissance

#### Initial port scan

```bash
nmap -n -Pn -T4 -p- $target_ip
```

**Open ports identified:**

| Port | Service (observed) |
|---:|---|
| 22/tcp | SSH |
| 80/tcp | HTTP (Apache) |
| 40891/tcp | Java RMI |
| 50000/tcp | HTTP (TeamCity UI) |

#### Service and version enumeration

```bash
nmap -n -Pn -T4 -sC -sV -p 22,80,40891,50000 $target_ip
```

**Key findings:**
- `22/tcp`: OpenSSH 8.2p1 (Ubuntu)  
- `80/tcp`: Apache httpd 2.4.41  
- `40891/tcp`: Java RMI  
- `50000/tcp`: TeamCity web interface (served over HTTP)

#### SSH validation

A direct connection attempt confirmed SSH was not available with password auth (public key required).

```bash
ssh $target_ip
# Permission denied (publickey).
```

#### Java RMI validation (40891/tcp)

```bash
nmap -p 40891 --script rmi-dumpregistry,rmi-vuln-classloader $target_ip
```

**Outcome (high level):**
- No accessible RMI registry entries were exposed
- No indication of an enabled remote class loader
- No immediately exploitable objects were disclosed during initial checks

#### HTTP validation (80/tcp)

Port **80** served a static “maintenance” page with no user input fields or interactive features suitable for exploitation during initial recon.

> Screenshot(s) removed for portability/OPSEC. (Local path in original draft: `./images/acessoinicialpage.png`)

---

### Initial access vector: TeamCity (50000/tcp)

Browsing `http://$target_ip:50000` revealed a publicly accessible TeamCity login page.

> Screenshot(s) removed for portability/OPSEC. (Local path in original draft: `./images/telainicial.png`)

From the login interface, the application version was identified as:

- **TeamCity 2023.11.3 (build 147512)**

---

### Vulnerability identification

TeamCity **2023.11.3** is affected by **CVE-2024-27198**, an authentication bypass issue that can allow unauthenticated access to certain protected endpoints due to request routing/processing behavior. JetBrains published fixes and guidance for affected on-premises versions. citeturn0search3turn0search6turn0search1

---

### Exploitation (high level)

To keep this write-up suitable for public/portfolio use, the exploitation details are intentionally **high level** and avoid providing a fully operational exploit chain.

**Attack chain (summarized):**
1. Use the authentication bypass condition to reach otherwise protected TeamCity functionality.
2. Obtain an authenticated context (e.g., administrative access) within TeamCity.
3. Leverage administrative capability to achieve server-side code execution (resulting in a shell as the service user on the host).
4. Use the shell to locate and read the user’s flag.

**Evidence of impact (what the bypass enables):**
- Authentication bypass can lead to administrative control of TeamCity if abused citeturn0search3turn0search4turn0search1
- The CVE is listed as known exploited, emphasizing real-world risk and urgency of patching citeturn0search6turn0search16

---

### Post-exploitation: flag retrieval

With command execution on the host, the target user context was confirmed and the flag was read from the user’s home directory.

```text
whoami
ubuntu

cat /home/<user>/flag.txt
THM{REDACTED}
```

> Note: the flag value is intentionally redacted here. Replace `THM{REDACTED}` with the exact output from your lab session.

---

### Conclusion (Red Team)

This lab demonstrates how a routing/authorization flaw in a complex web application can negate otherwise robust controls (tokens, CSRF, etc.). Operationally, the key lesson is to treat management interfaces (like CI/CD servers) as high-risk assets: restrict exposure, enforce strong access controls, and patch rapidly—especially for issues under active exploitation. citeturn0search3turn0search16

---

## Task 2 — Blue Team: Let’s Investigate

### Lab connection

After deploying the machine, Splunk becomes available at:

- `http://MACHINE_IP:8000`
- Username: `splunk`
- Password: `analyst123`

---

### Q1) Backdoor user created after exploitation

**Goal:** Identify evidence of user creation events. On Ubuntu, user creation commonly appears in `/var/log/auth.log` (and sometimes in `syslog`) with messages related to `useradd`/`adduser`.

**SPL (practical baseline):**
```spl
source="/var/log/auth.log" ("useradd" OR "adduser" OR "new user")
| table _time host source _raw
```

**If you want to extract the username from the raw line (optional):**
```spl
source="/var/log/auth.log" ("useradd" OR "adduser" OR "new user")
| rex field=_raw "(?i)new user:\s*name=(?<created_user>[^\s,]+)"
| rex field=_raw "(?i)useradd\[\d+\]:\s*new user:\s*name=(?<created_user2>[^\s,]+)"
| eval created_user=coalesce(created_user, created_user2)
| table _time host created_user _raw
```

---

### Q2) Malicious-looking package installed

**Goal:** Identify package installation records from `dpkg.log`. These typically show package name and version.

**SPL (broad):**
```spl
source="/var/log/dpkg.log" (" install " OR " installed ")
| table _time host source _raw
```

**SPL (if the lab specifies a known date window):**
```spl
source="/var/log/dpkg.log" (" install " OR " installed ") date_month=july date_mday=4
| table _time host _raw
```

> Tip: In practice, prefer starting broad, then narrowing by time to the compromise window.

---

## References

- JetBrains TeamCity blog post on CVE-2024-27198 / CVE-2024-27199 and upgrade guidance citeturn0search3  
- Rapid7 analysis of TeamCity authentication bypass vulnerabilities citeturn0search1  
- Wiz analysis of CVE-2024-27198 / CVE-2024-27199 citeturn0search4  
- NVD record for CVE-2024-27198 citeturn0search6  
- CISA KEV alert referencing active exploitation citeturn0search16  


> Written by **Nelson Hirt**
