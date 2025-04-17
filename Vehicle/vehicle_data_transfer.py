import hashlib
import socket, json
from datetime import datetime, timezone
from vehicle_helperfunction import *
from colorama import Fore, Style



def data_transfer(vehicle_socket, rsu_info, message):
    vehicle_credentials = extract_keys_from_file()
    vehicle_auth_token = extract_v_data_transfer()
    shared_key = generate_shareKey(vehicle_credentials['V PrivKey'], rsu_info['PubKey'])
    print(f"[Vehicle] Generating Message  ........")
    Message = message
    M1 = encrypt_message(json.dumps({
        'Message': Message,
        'AuthToken': vehicle_auth_token['AuthToken'],
        'AuthTokenSig': vehicle_auth_token['AuthTokenSig']
    }), shared_key)
    t1 = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    I1= hashlib.sha256((Message + vehicle_credentials['SID'] + vehicle_auth_token['AuthToken'] + vehicle_auth_token['AuthTokenSig'] + t1).encode()).hexdigest()
    data_packet = {
        'req_type': "data_transfer",
        'V_SID': vehicle_credentials['SID'],
        'V_PubKey': vehicle_credentials['V PubKey'],
        'ciphertext': binascii.hexlify(M1[0]).decode('utf-8'),
        'nonce': binascii.hexlify(M1[1]).decode('utf-8'),
        'authTag': binascii.hexlify(M1[2]).decode('utf-8'),
        'I1': I1,
        'T1': t1
    }
    print(f"[Vehicle] Sending Message To RSU: {data_packet}")
    vehicle_socket.sendall(json.dumps(data_packet).encode())
    try:
        ack = json.loads(vehicle_socket.recv(4096).decode())
    except:
        print(f"[Vehicle] Message Transfer Failed !!!!!!")
        exit()
    print(f"[Vehicle] Received Acknowledgement From RSU {ack}")
    M2 = json.loads(decrypt_message(ack, shared_key).decode())
    I2 = hashlib.sha256((ack['V_SID'] + str(M2['Status']) + M2['AuthToken'] + M2['AuthTokenSig']).encode()).hexdigest()
    if I2 != ack['I2']:
        print(Fore.RED + f"[Vehicle] Integrity Hash Verification Failed" + Style.RESET_ALL)
    print(Fore.GREEN + f"[Vehicle] Integrity Hash Verification Successful" + Style.RESET_ALL)
    if not verify_signature(M2['AuthToken'], M2['AuthTokenSig'], vehicle_credentials['TA PubKey']):
        print(Fore.RED + f"[Vehicle] Road Side Unit Authentication Token Signature Verification Failed" + Style.RESET_ALL)

    print(Fore.GREEN + f"[Vehicle] RSU Authentication Token Signature Verification Successful" + Style.RESET_ALL)
    if M2['Status'] == 200:
        print(Fore.GREEN + f" MESSAGE TRANSFER SUCCESSFUL" + Style.RESET_ALL)
