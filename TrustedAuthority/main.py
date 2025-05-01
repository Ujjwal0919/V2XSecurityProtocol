import socket, json, subprocess
from datetime import datetime, timezone
from ta_authentication import *
from ta_registration import *

TA_AUTH_SERVER_ADD = '0.0.0.0'
TA_AUTH_SERVER_PORT = 5522

def start_authentication_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((TA_AUTH_SERVER_ADD, TA_AUTH_SERVER_PORT))
    server_socket.listen()
    print("****************** Trusted Authority Authentication Server Started ****************")
    while True:
        rsu_socket, rsu_address = server_socket.accept()
        data = json.loads(rsu_socket.recv(4096).decode())
        T_r = datetime.now(timezone.utc)
        if data['req_type'] == 'auth_request':
            print(f"[TA] Received Authentication Request From RSU {data}")
            handle_authentication(rsu_socket, data, T_r)


if __name__ == "__main__":
    command = "python3 ta_registration.py"
    subprocess.Popen(["gnome-terminal", "--", "bash", "-c", f"{command}; exec bash"])
    try:
        start_authentication_server()
    except KeyboardInterrupt:
        print("[TA] Authentication Server Stopped By User")