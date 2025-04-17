import socket
from vehicle_authentication import *
from vehicle_data_transfer import *

RSU_SERVER_PORT = 8591
RSU_SERVER_BROAD_PORT = 4545
def connect_to_RSU():
    server_address = ('localhost', 8591)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)
    return client_socket

def receive_broadcast():
    buffer_size = 1024
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', RSU_SERVER_BROAD_PORT))
    print(f"[Vehicle] Searching For Nearby Road Side Unit ...")
    try:
        data, address = sock.recvfrom(buffer_size)
    except KeyboardInterrupt:
        print(f"[Vehicle] Vehicle Data Transfer Stopped...")
    finally:
        sock.close()
    return data


if __name__ == "__main__":
    rsu_info = json.loads(receive_broadcast().decode())
    print(f"[Vehicle] Received RSU Information from Broadcast:{rsu_info}")
    rsu_socket = connect_to_RSU()
    print(f"[Vehicle] Connected To Road Side Unit:{rsu_info['SID']}")
    print(f"************** VEHICLE MENU ***************")
    print(f"1. Perform Authentication")
    print(f"2. Perform Data Transfer (V2I)")
    choice = int(input("Enter Your Choice (1-2)"))
    if choice == 1:
        perform_authentication(rsu_socket, rsu_info)
    elif choice == 2:
        message = input("Enter the message: ")
        data_transfer(rsu_socket, rsu_info, message)
    else:
        print(f"Wrong Choice")