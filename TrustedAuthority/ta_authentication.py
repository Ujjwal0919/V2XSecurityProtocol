import hashlib, os, socket, json, threading, time
from datetime import datetime, timezone, timedelta
from colorama import Fore, Style
from ta_helperfuntion import *

threshold = timedelta(hours=0, minutes=0, seconds=4, microseconds=110268)

def handle_authentication(rsu_socket, data, T_r):
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
        rsu_authenticated = True
        I2 = hashlib.sha256((M2['V_SID'] + M2['N1'] + M2['v_res'] + M2['rsu_authToken'] + M2['rsu_authToken_Sig'] + data['T2']).encode()).hexdigest()
        if I2 != data['I2']:
            print(Fore.RED + f"[TA] Integrity Check Failed" + Style.RESET_ALL)
            rsu_socket.close()
            return
        print(Fore.GREEN + f"[TA] Integrity Check Successful" + Style.RESET_ALL)
        T2 = datetime.strptime(data['T2'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        if (T_r - T2) > threshold:
            print(T_r - T2)
            print(Fore.RED + f"Error: Time difference exceeds threshold" + Style.RESET_ALL)
            rsu_socket.close()
            return
        print(Fore.GREEN + f"Time difference is within acceptable limits" + Style.RESET_ALL)
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
        T2 = datetime.strptime(data['T2'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        if (T_r - T2) > threshold:
            print(T_r - T2)
            print(Fore.RED + f"Error: Time difference exceeds threshold" + Style.RESET_ALL)
            rsu_socket.close()
            return
        print(Fore.GREEN + f"Time difference is within acceptable limits" + Style.RESET_ALL)
        print(f"[TA] Road Side Unit Not Authenticated")
        print("[TA] Performing Road Side Unit Authentication")
        rsu_res = hashlib.sha256((M2['n2'] + rsu_credentials['RSU_Challenge']).encode()).hexdigest()
        if rsu_res != M2['rsu_res']:
            print(Fore.RED + f"[TA] Road Side Unit Authentication Failed" + Style.RESET_ALL)
            rsu_socket.close()
            return
        print(Fore.GREEN + f"[TA] Road Side Unit Authentication Successful" + Style.RESET_ALL)
        n3 = os.urandom(8).hex()
        SessionToken = hashlib.sha256((rsu_credentials['RSU_SID'] + M2['n2'] + n3).encode()).hexdigest()
        expiration_time = (datetime.now(timezone.utc) + timedelta(weeks=4)).strftime('%Y-%m-%dT%H:%M:%SZ')
        rsu_SessionToken = f"{SessionToken}:{expiration_time}"
        rsu_SessionTokenSig = create_signature(rsu_SessionToken, ta_credentials['TA_Priv_Key'])
        print(f"[TA] Generated RSU Session Token: {rsu_SessionToken}")
        print(f"[TA] Generated RSU Session Token Signature: {rsu_SessionTokenSig}")
        print(f"[TA] Performing Vehicle Authentication")

    # PERFORM VEHICLE AUTHENTICATION

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