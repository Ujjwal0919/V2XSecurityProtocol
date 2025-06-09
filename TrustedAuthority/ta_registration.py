import sqlite3
import threading, socket, json, os
import time
from tinyec import registry
import secrets


#curve = registry.get_curve('BRAINPOOLP160r1') # 160 Bit
#curve = registry.get_curve('BRAINPOOLP192r1')  # 192-bit (current)
curve = registry.get_curve('brainpoolP256r1') # 256-bit
#curve = registry.get_curve('BRAINPOOLP320r1')  # 320-bit
#curve = registry.get_curve('BRAINPOOLP512r1')  # 512-bit


ta_public_key, ta_private_key = "H" , "H"
TA_REG_SERVER_ADD = '127.0.0.1'  # Bind to localhost for security
TA_REG_SERVER_PORT = 4444

def save_rsu_data(SID, Chall, PubKey):
    conn =sqlite3.connect("./DataBases/TAdb.db")
    cursor = conn.cursor()
    query = "INSERT INTO R_Data (SID, Chall, PubKey) VALUES (?,?,?)"
    cursor.execute(query, (SID, Chall, PubKey))
    conn.commit()
    conn.close()

def save_v_data(SID, Chall, PubKey):
    conn =sqlite3.connect("./DataBases/TAdb.db")
    cursor = conn.cursor()
    query = "INSERT INTO V_Data (SID, Chall, PubKey) VALUES (?,?,?)"
    cursor.execute(query, (SID, Chall, PubKey))
    conn.commit()
    conn.close()


def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]

def ecc_calc_encryption_keys():
    global ta_private_key, ta_public_key
    ta_private_key = secrets.randbelow(curve.field.n)  # Generation of Private Key
    ta_public_key_point = ta_private_key * curve.g
    ta_public_key = compress_point(ta_public_key_point)  # Compression of Public Key
    print("Keys Generated For Trusted Authority")
    print(f"--> Private Key: {ta_private_key}")
    print(f"--> Public Key: {ta_public_key}")
    conn = sqlite3.connect("./DataBases/TAdb.db")
    cursor = conn.cursor()
    query = "INSERT INTO TA_Keys (PubKey, PrivKey) VALUES (?,?)"
    cursor.execute(query, (str(ta_public_key), str(ta_private_key)))
    conn.commit()
    conn.close()

def handle_rsu_registration(client_socket, data):
    time_start = time.time()
    print(f"Received: RSU Public Key: {data['RSU_Pub_Key']}")
    chall = os.urandom(16).hex()
    rsu_registration_response = json.dumps({'TA_Pub_Key': ta_public_key, 'Chall': chall})
    client_socket.sendall(rsu_registration_response.encode())
    save_rsu_data(data['RSU_SID'], chall, data['RSU_Pub_Key'].encode())
    time_end = time.time()
    print(f"Time taken for Registration: {time_end - time_start:.6f} seconds")
    print("********************** Registration Complete *********************")
    client_socket.close()

def handle_v_registration(client_socket, data):
    time_start = time.time()
    print(f"Received: Vehicle Public Key: {data['V_Pub_Key']}")
    chall = os.urandom(16).hex()
    rsu_registration_response = json.dumps({'TA_Pub_Key': ta_public_key, 'Chall': chall})
    client_socket.sendall(rsu_registration_response.encode())
    save_v_data(data['V_SID'], chall, data['V_Pub_Key'].encode())
    time_end = time.time()
    print(f"Time Taken for Registration: {time_end - time_start: 6f} seconds")
    print("********************** Registration Complete *********************")
    client_socket.close()

def start_registration_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((TA_REG_SERVER_ADD, TA_REG_SERVER_PORT))
    server_socket.listen()
    print(f"****************** Trusted Authority Registration Server Started ****************")

    while True:
        client_socket, client_address = server_socket.accept()
        data = json.loads(client_socket.recv(1024).decode())
        if 'RSU_SID' in data:
            print(f" Received Registration Request From Road Side Unit {data['RSU_SID']}")
            rsu_registration_thread = threading.Thread(target=handle_rsu_registration, args=(client_socket, data))
            rsu_registration_thread.start()
        elif 'V_SID' in data:
            print(f" Received Registration Request From Vehicle {data['V_SID']}")
            v_registration_thread = threading.Thread(target=handle_v_registration, args=(client_socket, data))
            v_registration_thread.start()
        else:
            print(f"--> Wrong Request Received: ")

def main():
    keys_generated = False
    while not keys_generated:
        conn = sqlite3.connect("./DataBases/TAdb.db")
        cursor = conn.cursor()
        query = "SELECT * FROM TA_Keys"
        cursor.execute(query)
        results = cursor.fetchone()
        if results is None:
            ecc_calc_encryption_keys()
            keys_generated = True
        else:
            global ta_public_key, ta_private_key
            ta_public_key, ta_private_key = results[0], results[1]
            print("************** TA Generated Keys *******************")
            print(f"-->TA Public Key: {ta_public_key}")
            print(f"-->TA Private Key: {ta_private_key} ")
            keys_generated = True
if __name__ == "__main__":
    try:
        main()
        start_registration_server()
    except KeyboardInterrupt:
        print(" ********** Registration Server Stooped ***********")