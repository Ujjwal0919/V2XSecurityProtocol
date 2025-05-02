import hashlib
import os
import socket, json
from datetime import datetime, timezone, timedelta
from rsu_helperfunction import *
from rsu_data_transfer import *
from colorama import Fore, Style

threshold = timedelta(hours=0, minutes=0, seconds=4, microseconds=110268)
TA_ADDRESS = '192.168.0.188'
TA_PORT = 5522

def connect_to_ta():
    server_address = (TA_ADDRESS, TA_PORT)
    ta_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ta_socket.connect(server_address)
    print("[RSU] Connected To Trusted Authority")
    return ta_socket

def handle_vehicle_offline_authentication(vehicle_socket, data, T_r):
    vehicle_chall = fetch_vehicle_cache(data['V_SID'])
    rsu_credentials = extract_keys_from_file()
    shared_key_v = generate_shareKey(rsu_credentials['RSU PrivKey'], data['V_PubKey'])
    M1 = json.loads(decrypt_message(data, shared_key_v).decode())
    I1 = hashlib.sha256((data['V_SID'] + M1['n1'] + M1['v_res'] + data['T1']).encode()).hexdigest()
    if I1 != data['I1']:
        print(Fore.RED + f"[RSU] Integrity Check Failed !!" + Style.RESET_ALL)
        exit()
    print(Fore.GREEN + f"[RSU] Integrity Check Successful !!" + Style.RESET_ALL)
    T1 = datetime.strptime(data['T1'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    if (T_r - T1) > threshold:
        print(T_r - T1)
        print(Fore.RED + f"Error: Time difference exceeds threshold" + Style.RESET_ALL)
        vehicle_socket.close()
        return
    print(Fore.GREEN + f"Time difference is within acceptable limits" + Style.RESET_ALL)
    vehicle_res = hashlib.sha256((M1['n1'] + vehicle_chall).encode()).hexdigest()
    if vehicle_res != M1['v_res']:
        print(Fore.RED + f"[RSU] Vehicle Authentication Failed" + Style.RESET_ALL)
        vehicle_socket.close()
        return
    print(Fore.GREEN + f"[RSU] Vehicle Verified In Offline Mode" + Style.RESET_ALL)
    N2 = os.urandom(8).hex()
    rsu_res = hashlib.sha256((N2 + vehicle_chall).encode()).hexdigest()

    #Generating Session Tokens & Signature for Vehicle
    SessionToken = hashlib.sha256((data['V_SID'] + M1['n1'] + N2).encode()).hexdigest()
    expiration_time = (datetime.now(timezone.utc) + timedelta(weeks=4)).strftime('%Y-%m-%dT%H:%M:%SZ')
    v_SessionToken = f"{rsu_credentials['SID']}:{SessionToken}:{expiration_time}"
    v_SessionTokenSig = create_signature(v_SessionToken, rsu_credentials['RSU PrivKey'])
    t2 = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    print(f"[RSU] Generated Vehicle Session Token: {v_SessionToken}")
    print(f"[RSU] Generated Vehicle Session Token Signature: {v_SessionTokenSig}")
    M2 = encrypt_message(json.dumps({
        'V_SID': data['V_SID'],
        'n2': N2,
        'rsu_res': rsu_res,
        'v_sessionToken': v_SessionToken,
        'v_sessionTokenSig': v_SessionTokenSig,
        'T2': t2
    }), shared_key_v)

    I2 = hashlib.sha256((data['V_SID'] + M1['n1'] + M1['v_res'] + N2 + rsu_res + t2).encode()).hexdigest()
    data_packet = {
        'V_SID': data['V_SID'],
        'ciphertext': binascii.hexlify(M2[0]).decode('utf-8'),
        'nonce': binascii.hexlify(M2[1]).decode('utf-8'),
        'authTag': binascii.hexlify(M2[2]).decode('utf-8'),
        'I2': I2,
        'T2': t2
    }
    print(f"[RSU] Sending Authentication Response To Vehicle {data_packet}")
    vehicle_socket.sendall(json.dumps(data_packet).encode())
    print(f" ************** AUTHENTICATION COMPLETE *******************")
    return

def handle_vehicle_authentication(vehicle_socket, data, T_r):
    rsu_authenticated = False
    rsu_credentials = extract_keys_from_file()
    shared_key_v = generate_shareKey(rsu_credentials['RSU PrivKey'], data['V_PubKey'])
    M1 = json.loads(decrypt_message(data, shared_key_v).decode())
    I1 = hashlib.sha256((data['V_SID'] + M1['n1'] + M1['v_res'] + data['T1']).encode()).hexdigest()
    shared_key_ta = generate_shareKey(rsu_credentials['RSU PrivKey'], rsu_credentials['TA PubKey'])
    if I1 != data['I1']:
        print(Fore.RED + f"[RSU] Integrity Check Failed !!" + Style.RESET_ALL)
        exit()
    print(Fore.GREEN + f"[RSU] Integrity Check Successful !!" + Style.RESET_ALL)
    T1 = datetime.strptime(data['T1'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    if (T_r - T1) > threshold:
        print(T_r - T1)
        print(Fore.RED + f"[RSU] Error: Time difference exceeds threshold" + Style.RESET_ALL)
        vehicle_socket.close()
        return
    print(Fore.GREEN + f"[RSU]Time difference is within acceptable limits" + Style.RESET_ALL)
    t2 = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    if os.path.isfile('rsu_data_transfer.txt'):
        print(f"[RSU] Already Authenticated with Trusted Authority")
        rsu_authenticated = True
        rsu_authTokens = extract_rsu_data_transfer()
        M2 = encrypt_message(json.dumps({
            'V_SID': data['V_SID'],
            'N1': M1['n1'],
            'v_res': M1['v_res'],
            'rsu_authToken': rsu_authTokens['AuthToken'],
            'rsu_authToken_Sig': rsu_authTokens['AuthTokenSig']
            }), shared_key_ta)
        I2 = hashlib.sha256((data['V_SID'] + M1['n1'] + M1['v_res'] + rsu_authTokens['AuthToken'] + rsu_authTokens['AuthTokenSig'] + t2).encode()).hexdigest()

    else:
        print("[RSU] RSU is Not Authenticated with Trusted Authority")
        n2, rsu_res = generate_nonce_and_response(rsu_credentials['Challenge'])
        M2 = encrypt_message(json.dumps({
                'V_SID': data['V_SID'],
                'N1': M1['n1'],
                'v_res': M1['v_res'],
                'n2': n2,
                'rsu_res': rsu_res
            }), shared_key_ta)
        I2 = hashlib.sha256((data['V_SID'] + M1['n1'] + M1['v_res'] + n2 + rsu_res + t2).encode()).hexdigest()

    data_packet = {
        'req_type': "auth_request",
        'RSU_SID': rsu_credentials['SID'],
        'ciphertext': binascii.hexlify(M2[0]).decode('utf-8'),
        'nonce': binascii.hexlify(M2[1]).decode('utf-8'),
        'authTag': binascii.hexlify(M2[2]).decode('utf-8'),
        'I2': I2,
        'T2': t2
    }
    print(f"[RSU] Sending Message to Trusted Authority: {data_packet}")
    ta_socket = connect_to_ta()
    ta_socket.sendall(json.dumps(data_packet).encode())
    try:
        ta_response = json.loads(ta_socket.recv(4096).decode())
        T_r = datetime.now(timezone.utc)
    except:
        print(Fore.RED + f"[RSU] Authentication Failed !!" + Style.RESET_ALL)
    print(f"[RSU] Received Trusted Authority Response: {ta_response}")
    M3 = json.loads(decrypt_message(ta_response, shared_key_ta).decode())
    if rsu_authenticated == True:
        I3 = hashlib.sha256((rsu_credentials['SID'] + M3['N4'] + M3['v_ta_res'] + ta_response['T3']).encode()).hexdigest()
    else:
        I3 = hashlib.sha256((rsu_credentials['SID'] + M3['N4'] + M3['v_ta_res'] + M3['rsu_ta_res'] + M3['SessionKeyRSU'] + M3['SessionKeySig'] + ta_response['T3'] ).encode()).hexdigest()
    if I3!= ta_response['I3']:
        print(Fore.RED + f"[RSU] Integrity Check Failed !!" + Style.RESET_ALL)
        exit()
    print(Fore.GREEN + f"[RSU] Integrity Check Successful" + Style.RESET_ALL)
    T3 = datetime.strptime(ta_response['T3'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    if (T_r - T3) > threshold:
        print(T_r - T3)
        print(Fore.RED + f"Error: Time difference exceeds threshold" + Style.RESET_ALL)
        vehicle_socket.close()
        return
    print(Fore.GREEN + f"Time difference is within acceptable limits" + Style.RESET_ALL)

    if rsu_authenticated == False:
        rsu_ta_res = hashlib.sha256((M3['N4'] + rsu_credentials['Challenge']).encode()).hexdigest()
        if rsu_ta_res != M3['rsu_ta_res']:
            print(Fore.RED + f"[RSU] TA Authentication Failed" + Style.RESET_ALL)
            exit()
        print(Fore.GREEN + f"[RSU] TA Authentication Successful")
        print(f"[RSU] Saving RSU's Authentication Token and Signature")
        save_rsu_data_transfer(rsu_credentials['SID'], M3['SessionKeyRSU'], M3['SessionKeySig'])
    if 'v_cred'  not in M3:
        print(Fore.RED + f"[RSU] Vehicle Authentication Failed !!" + Style.RESET_ALL)
        vehicle_socket.close()
        return
    print(Fore.GREEN + f"[RSU] Vehicle Authentication Successful" + Style.RESET_ALL)
    N5 = os.urandom(8).hex()
    SessionToken = hashlib.sha256((data['V_SID'] + M1['n1'] + N5 ).encode()).hexdigest()
    expiration_time = (datetime.now(timezone.utc) + timedelta(weeks=4)).strftime('%Y-%m-%dT%H:%M:%SZ')
    v_SessionToken = f"{rsu_credentials['SID']}:{SessionToken}:{expiration_time}"
    v_SessionTokenSig = create_signature(v_SessionToken, rsu_credentials['RSU PrivKey'])
    print(f"[RSU] Generated Vehicle Session Token: {v_SessionToken}")
    print(f"[RSU] Generated Vehicle Session Token Signature: {v_SessionTokenSig}")
    M4 = encrypt_message(json.dumps({
            'V_SID': data['V_SID'],
            'N4': M3['N4'],
            'v_ta_res': M3['v_ta_res'],
            'N5': N5,
            'v_SessionToken': v_SessionToken,
            'v_SessionTokenSig': v_SessionTokenSig
        }), shared_key_v)
    T4 = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    I4 = hashlib.sha256((data['V_SID'] + M3['N4'] + M3['v_ta_res'] + N5 + v_SessionToken + v_SessionTokenSig + T4).encode()).hexdigest()
    data_packet = {
            'V_SID': data['V_SID'],
            'ciphertext': binascii.hexlify(M4[0]).decode('utf-8'),
            'nonce': binascii.hexlify(M4[1]).decode('utf-8'),
            'authTag': binascii.hexlify(M4[2]).decode('utf-8'),
            'I4': I4,
            'T4': T4
        }
    print(f"[RSU] Sending Authentication Response to Vehicle: {data_packet}")
    print(f"[RSU] Saving Vehicle Credentials in Cache Database")
    vehicle_cred = json.loads(M3['v_cred'])
    save_vehicle_creds(vehicle_cred['V_SID'], vehicle_cred['V_Chall'])
    #CHANGE THIS TO USE LORA
    vehicle_socket.sendall(json.dumps(data_packet).encode())

    print(Fore.GREEN + f"*********** Authentication Complete ***********")
