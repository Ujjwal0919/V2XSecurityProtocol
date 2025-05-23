import socket, json, threading, os
import time

from tinyec import registry
import secrets


SID = os.urandom(8).hex()

#curve = registry.get_curve('BRAINPOOLP160r1') # 160 Bit
#curve = registry.get_curve('BRAINPOOLP192r1')  # 192-bit (current)
curve = registry.get_curve('brainpoolP256r1') # 256-bit
#curve = registry.get_curve('BRAINPOOLP320r1')  # 320-bit
#curve = registry.get_curve('BRAINPOOLP512r1')  # 512-bit

def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]

def ecc_calc_encryption_keys():
    v_private_key = secrets.randbelow(curve.field.n)  # Generation of Private Key
    v_public_key = v_private_key * curve.g  # Generation of Public Key
    return v_private_key, v_public_key


def store_rsu_info(chall, rsu_priv_key, rsu_pub_key, ta_pub_key):
    with open('v_keys.txt', 'w') as file:
        file.write(f"SID: {SID}")
        file.write(f"\nChallenge: {chall}")
        file.write(f"\nV PrivKey: {rsu_priv_key}")
        file.write(f"\nV PubKey: {rsu_pub_key}")
        file.write(f"\nTA PubKey: {ta_pub_key}")
        print("Vehicle SID, Challenge & Keys Stored in v_keys.txt")



def send_registration_request(server_address):
    time_start = time.time()
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)
    rsu_priv_key , rsu_pub_key = ecc_calc_encryption_keys()
    print(f"-->Vehicle Public Key: {rsu_priv_key}")
    print(f"-->Vehicle Private Key: {compress_point(rsu_pub_key)}")
    print(f"-->Sending Vehicle Public Key to Trusted Authority")
    registration_request = json.dumps({'V_SID': SID, 'V_Pub_Key': compress_point(rsu_pub_key)})
    client_socket.sendall(registration_request.encode())
    response = json.loads(client_socket.recv(1024).decode())
    print(f"-->Received Trusted Authority Public Key: {response['TA_Pub_Key']}")
    store_rsu_info(response['Chall'], rsu_priv_key, compress_point(rsu_pub_key), response['TA_Pub_Key'])
    print("****************** Registration Complete ******************")
    client_socket.close()
    time_end = time.time()
    print(f"Time taken for Registration: {time_end - time_start:.6f} seconds")


def main():
    fms_server_address = ('127.0.0.1', 4444)
    send_registration_request(fms_server_address)

if __name__ == "__main__":
    main()