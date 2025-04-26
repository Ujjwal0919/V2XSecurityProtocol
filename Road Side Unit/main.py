import socket, subprocess
from rsu_authentication import *
from rsu_data_transfer import *
from rsu_broadcast import *

RSU_SERVER_ADD = "0.0.0.0"
RSU_SERVER_PORT = 8594

def start_rsu_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((RSU_SERVER_ADD, RSU_SERVER_PORT))
    server_socket.listen()
    print("****************** RSU Server Started ****************")
    while True:
        vehicle_socket, client_address = server_socket.accept()
        data = json.loads(vehicle_socket.recv(1024).decode())
        T_r = datetime.now(timezone.utc)
        print(f"[RSU] Received Authentication Request From Vehicle: {data}")
        if data['req_type'] == "auth_Request":
            vehicle_chall = fetch_vehicle_cache(data['V_SID'])
            if vehicle_chall:
                print(f"[RSU] Vehicle Information Found in Cache..")
                print(f"[RSU] Performing Offline Authentication")
                handle_vehicle_offline_authentication(vehicle_socket, data, T_r)
            else:
                print(f"[RSU] Vehicle Information Not Found In Cache..")
                print(f"[RSU] Performing Online Authentication..")
                handle_vehicle_authentication(vehicle_socket, data, T_r)
        if data['req_type'] == "data_transfer":
            print(f"[RSU] Received Data Transfer Request From Vehicle: {data}")
            handle_data_transfer(vehicle_socket, data)


if __name__ == "__main__":
    command = "python3 rsu_broadcast.py"
    subprocess.Popen(["gnome-terminal", "--", "bash", "-c", f"{command}; exec bash"])
    try:
        start_rsu_server()
    except KeyboardInterrupt:
        print("[RSU] Road Side Unit Server Stopped By User")