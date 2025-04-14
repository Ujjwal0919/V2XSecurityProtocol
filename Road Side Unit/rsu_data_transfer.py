import binascii
from datetime import datetime, timezone

from rsu_helperfunction import *
import json, hashlib
from colorama import Fore, Style

def handle_data_transfer(vehicle_socket, data):
    rsu_credentials = extract_keys_from_file()
    rsu_authtoken = extract_rsu_data_transfer()
    shared_key_v = generate_shareKey(rsu_credentials['RSU PrivKey'], data['V_PubKey'])
    M1 = json.loads(decrypt_message(data, shared_key_v).decode())
    I1 = hashlib.sha256((M1['Message'] + data['V_SID'] + M1['AuthToken'] + M1['AuthTokenSig'] + data['T1']).encode()).hexdigest()
    if I1 != data['I1']:
        print(Fore.RED + f"[RSU] Error: Integrity Check Failed !!" + Style.RESET_ALL)
    print(Fore.GREEN + f"[RSU] Integrity Check Successful" + Style.RESET_ALL)
    auth_rsu_sid = M1['AuthToken'].split(":")[0]
    print(f"[RSU] Fetching Authenticator RSU Public Key")
    auth_rsu_pubkey = rsu_pub_key(auth_rsu_sid)
    if not verify_signature(M1['AuthToken'], M1['AuthTokenSig'], auth_rsu_pubkey):
        print(Fore.RED + f"[RSU] Authentication Token Signature Verification Failed" + Style.RESET_ALL)

    print(Fore.GREEN + f"[RSU] Authentication Token Signature Verified Successfully" + Style.RESET_ALL)
    print(Fore.GREEN + f"[RSU] Vehicle Verified Successfully" + Style.RESET_ALL)
    print(Fore.BLUE + f"Data Received From Vehicle: {data['V_SID']} is {M1['Message']}" + Style.RESET_ALL)
    Status = 200
    # Generating Acknowledgement

    M2 = encrypt_message(json.dumps({
        'Status': Status,
        'AuthToken': rsu_authtoken['AuthToken'],
        'AuthTokenSig': rsu_authtoken['AuthTokenSig']
    }), shared_key_v)
    t2 = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    I2 = hashlib.sha256((data['V_SID'] + str(Status) + rsu_authtoken['AuthToken'] + rsu_authtoken['AuthTokenSig']).encode()).hexdigest()
    data_packet = {
        'req_type': 'Acknowledgement',
        'V_SID': data['V_SID'],
        'ciphertext': binascii.hexlify(M2[0]).decode('utf-8'),
        'nonce': binascii.hexlify(M2[1]).decode('utf-8'),
        'authTag': binascii.hexlify(M2[2]).decode('utf-8'),
        'I2': I2,
        't2': t2
    }
    print(f"[RSU] Sending Acknowledgement to Vehicle: {data_packet}")
    vehicle_socket.sendall(json.dumps(data_packet).encode())
    print(Fore.GREEN + f" MESSAGE TRANSFER SUCCESSFUL" + Style.RESET_ALL)
