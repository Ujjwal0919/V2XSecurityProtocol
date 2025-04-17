import socket, json
from datetime import datetime, timezone
from colorama import Fore, Style
from vehicle_helperfunction import *


def perform_authentication(rsu_socket, rsu_info):
    start_time = time.time()
    v_credentials = extract_keys_from_file()
    print(f"[Vehicle] Starting Authentication with Nearest Road Side Unit")
    n1, v_res = generate_nonce_and_response(v_credentials['Challenge'])
    t1 = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    sharedkey = generate_shareKey(v_credentials['V PrivKey'], rsu_info['PubKey'])
    M1 = encrypt_message(json.dumps({'v_res': v_res, 'n1': n1, 't1': t1}), sharedkey)
    I1 = I1 = hashlib.sha256((v_credentials['SID'] + n1 + v_res + t1).encode()).hexdigest()
    data_packet = {
        'req_type': "auth_Request",
        'V_SID': v_credentials['SID'],
        'V_PubKey': v_credentials['V PubKey'],
        'ciphertext': binascii.hexlify(M1[0]).decode('utf-8'),
        'nonce': binascii.hexlify(M1[1]).decode('utf-8'),
        'authTag': binascii.hexlify(M1[2]).decode('utf-8'),
        'I1': I1,
        'T1': t1
    }
    print(f"[Vehicle] Sending Message to RSU: {data_packet}")
    rsu_socket.sendall(json.dumps(data_packet).encode())
    try:
        rsu_response = json.loads(rsu_socket.recv(4096).decode())
    except:
        print(Fore.RED + f"[Vehicle]")
    print(f"[Vehicle] Received Authentication Response from RSU: {rsu_response}")
    M = json.loads(decrypt_message(rsu_response, sharedkey).decode())
    if 'rsu_res' in M:
        # OFFLINE AUTHENTICATION
        print(f"[Vehicle] Performing Offline Authentication")
        rsu_res = hashlib.sha256((M['n2'] + v_credentials['Challenge']).encode()).hexdigest()
        if rsu_res!= M['rsu_res']:
            print(Fore.RED + f"[Vehicle] RSU Authentication Failed" + Style.RESET_ALL)
            rsu_socket.close()
            exit()
        print(Fore.GREEN + f"[Vehicle] RSU Authentication Successful" + Style.RESET_ALL)
        save_v_data_transfer(v_credentials['SID'], M['v_sessionToken'], M['v_sessionTokenSig'])
        print(f"*************** AUTHENTICATION SUCCESSFUL ***********")
    else:
        # ONLINE AUTHENTICATION
        M4 = M
        I4 = hashlib.sha256((v_credentials['SID'] + M4['N4'] + M4['v_ta_res'] + M4['N5'] + M4['v_SessionToken'] + M4['v_SessionTokenSig'] + rsu_response['T4']).encode()).hexdigest()
        if I4!= rsu_response['I4']:
            print(Fore.RED + f"[Vehicle] Integrity Check Failed" + Style.RESET_ALL)
            rsu_socket.close()
            exit()
        print(Fore.GREEN + f"[Vehicle] Integrity Check Successful" + Style.RESET_ALL)
        v_ta_res = hashlib.sha256((M4['N4'] + v_credentials['Challenge']).encode()).hexdigest()
        if v_ta_res!= M4['v_ta_res']:
            print(Fore.RED + f"[Vehicle] TA Authentication Failed" + Style.RESET_ALL)
            rsu_socket.close()
            exit()
        print(Fore.GREEN + f"[Vehicle] TA Authentication Successful" + Style.RESET_ALL)
        print(f"[RSU] Saving Session Token: {M4['v_SessionToken']}")
        print(f"[RSU] Saving Session Token Signature: {M4['v_SessionTokenSig']}")
        save_v_data_transfer(v_credentials['SID'], M4['v_SessionToken'], M4['v_SessionTokenSig'])
        print(Fore.GREEN + f"************* AUTHENTICATION COMPLETE *********" + Style.RESET_ALL)
    end_time = time.time()
    print(f"Time Taken For Authentication: {end_time - start_time} seconds")