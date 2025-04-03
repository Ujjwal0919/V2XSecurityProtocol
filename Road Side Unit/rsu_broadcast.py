import socket, json, time
from rsu_helperfunction import extract_keys_from_file, extract_rsu_data_transfer

def create_broadcast_socket():
    broadcast_address = '<broadcast>'
    port = 4545
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    return broadcast_address, port, sock

def broadcast_message():
    broadcast_address, port, sock = create_broadcast_socket()
    rsu_credentials = extract_keys_from_file()
    print(f"[RSU] Broadcasting RSU Details To Nearby Vehicles... (Press Ctrl+C to stop)..")
    message = json.dumps({'SID': rsu_credentials['SID'], 'PubKey': rsu_credentials['RSU PubKey']})
    try:
        while True:
            sock.sendto(message.encode(), (broadcast_address, port))
            print(f"[RSU] Broadcast RSU Info: {message}")
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"[RSU] Broadcasting stopped.")
    finally:
        sock.close()

if __name__ == "__main__":
    try:
        broadcast_message()
    except KeyboardInterrupt:
        print(f"[RSU] Broadcasting stopped.")
    finally:
        print(f"[RSU] Shutting down...")