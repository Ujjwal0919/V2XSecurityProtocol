import hashlib
import os
import socket, json, threading
import time
from datetime import datetime, timezone, timedelta
from colorama import Fore, Style
from ta_helperfuntion import *



def handle_rsu_authentication(rsu_socket, data):
    rsu_authenticated = False
    rsu_credentials = extract_rsu_credentials(data['RSU_SID'])
    ta_credentials = extract_ta_credentials()
    if rsu_credentials is None:
        print(Fore.RED + f"[TA] RSU Not Found in Database: {data['RSU_SID']}" + Style.RESET_ALL)
        rsu_socket.close()
        return
    shared_key_rsu = generate_shareKey(ta_credentials['TA_Priv_Key'], rsu_credentials['RSU_Pub_Key'])
    M2 = json.loads(decrypt_message(data, shared_key_rsu).decode())
    if 'rsu_authToken' in M2:
        I2 = hashlib.sha256((M2['V_SID'] + M2['N1'] + M2['v_res'] + M2['rsu_authToken'] + M2['rsu_authToken_Sig'] + data['T2']).encode()).hexdigest()
        if I2 != data['I2']:
            print(Fore.RED + f"[TA] Integrity Check Failed" + Style.RESET_ALL)
            rsu_socket.close()
            return
        print(Fore.GREEN + f"[TA] Integrity Check Successful" + Style.RESET_ALL)
        print(f"[TA] Road Side Unit Already Authenticated")
        print(f"[TA] Verifying Authentication Token")
        if verify_signature(M2['rsu_authToken'], M2['rsu_authToken_Sig'], ta_credentials['TA_Pub_Key']):
            print(Fore.GREEN + f"[TA] Road Side Unit Authentication Token Verified" + Style.RESET_ALL)
            rsu_authenticated = True
        N4 = os.urandom(8).hex()

    else:
        I2 = hashlib.sha256((M2['V_SID'] + M2['N1'] + M2['v_res'] + M2['n2'] + M2['rsu_res'] + data['T2']).encode()).hexdigest()
        if I2 != data['I2']:
            print(Fore.RED + f"[TA] Integrity Check Failed" + Style.RESET_ALL)
            rsu_socket.close()
            return
        print(Fore.GREEN + f"[TA] Integrity Check Successful" + Style.RESET_ALL)
        print("[TA] Performing RSU Authentication")
        rsu_res = hashlib.sha256((M2['n2'] + rsu_credentials['RSU_Challenge']).encode()).hexdigest()
        if rsu_res != M2['rsu_res']:
            print(Fore.RED + f"[TA] RSU Authentication Failed" + Style.RESET_ALL)
        print(Fore.GREEN + f"[TA] RSU Authentication Successful" + Style.RESET_ALL)
        n3 = os.urandom(8).hex()
        SessionToken = hashlib.sha256((rsu_credentials['RSU_SID'] + M2['n2'] + n3).encode()).hexdigest()
        expiration_time = (datetime.now(timezone.utc) + timedelta(weeks=4)).strftime('%Y-%m-%dT%H:%M:%SZ')
        rsu_SessionToken = f"{SessionToken}:{expiration_time}"
        rsu_SessionTokenSig = create_signature(rsu_SessionToken, ta_credentials['TA_Priv_Key'])
        print(f"[TA] Generated RSU Session Token: {rsu_SessionToken}")
        print(f"[TA] Generated RSU Session Token Signature: {rsu_SessionTokenSig}")
        print(f"[TA] Performing Vehicle Authentication")

    v_credentials = extract_v_credentials(M2['V_SID'])
    v_res = hashlib.sha256((M2['N1'] + v_credentials['V_Challenge']).encode()).hexdigest()
    if v_res != M2['v_res']:
        print(Fore.RED + f"[TA] Vehicle Authentication Failed" + Style.RESET_ALL)
    print(Fore.GREEN + f"[TA] Vehicle Authentication Successful" + Style.RESET_ALL)
    N4 = os.urandom(8).hex()
    res_v_ta = hashlib.sha256((N4 + v_credentials['V_Challenge']).encode()).hexdigest()
    res_rsu_ta = hashlib.sha256((N4 + rsu_credentials['RSU_Challenge']).encode()).hexdigest()
    T3 = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    vehicle_cred = json.dumps({
        'V_SID': M2['V_SID'],
        'V_Chall': v_credentials['V_Challenge']
    })
    if rsu_authenticated == False:
        M3 = encrypt_message(json.dumps({
        'N4': N4,
        'v_ta_res': res_v_ta,
        'v_cred': vehicle_cred,
        'rsu_ta_res': res_rsu_ta,
        'SessionKeyRSU': rsu_SessionToken,
        'SessionKeySig': rsu_SessionTokenSig
        }), shared_key_rsu)
        I3 = hashlib.sha256((rsu_credentials['RSU_SID'] + N4 + res_v_ta + res_rsu_ta + rsu_SessionToken + rsu_SessionTokenSig + T3).encode()).hexdigest()
    else:
        M3 = encrypt_message(json.dumps({
        'N4': N4,
        'v_ta_res': res_v_ta,
        'v_cred': vehicle_cred
        }), shared_key_rsu)
        I3 = hashlib.sha256((rsu_credentials['RSU_SID'] + N4 + res_v_ta  + T3).encode()).hexdigest()
    data_packet = {
        'RSU_SID': rsu_credentials['RSU_SID'],
        'ciphertext': binascii.hexlify(M3[0]).decode('utf-8'),
        'nonce': binascii.hexlify(M3[1]).decode('utf-8'),
        'authTag': binascii.hexlify(M3[2]).decode('utf-8'),
        'I3': I3,
        'T3': T3
    }
    print(f"[TA] Sending Authentication Response To Trusted Authority: {data_packet}")
    rsu_socket.sendall(json.dumps(data_packet).encode())
    print(f"*********************** AUTHENTICATION SUCCESSFUL ****************")
def start_authentication_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 5522))
    server_socket.listen()
    print("****************** Authentication Server Started ****************")
    while True:
        rsu_socket, rsu_address = server_socket.accept()
        data = json.loads(rsu_socket.recv(4096).decode())
        if data['req_type'] == 'auth_request':
            print(f"[TA] Received Authentication Request From RSU {data}")
            handle_rsu_authentication(rsu_socket, data)


if __name__ == "__main__":
    try:
        start_authentication_server()
    except KeyboardInterrupt:
        print("[TA] Authentication Server Stopped By User")