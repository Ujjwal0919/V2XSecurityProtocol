import binascii
import hashlib, os
import secrets
import sqlite3
import sys
import time, json
from datetime import datetime, timezone

from tinyec import registry
from tinyec.ec import Point
from Crypto.Cipher import AES


#curve = registry.get_curve('BRAINPOOLP160r1') # 160 Bit
#curve = registry.get_curve('BRAINPOOLP192r1')  # 192-bit
curve = registry.get_curve('brainpoolP256r1') # 256-bit
#curve = registry.get_curve('BRAINPOOLP320r1')  # 320-bit
#curve = registry.get_curve('BRAINPOOLP512r1')  # 512-bit

def generate_shareKey(TA_PrivKey, Node_PubKey):
    TA_PrivKey_INT = int(TA_PrivKey)
    RSU_PubKey_Point = decompress_point(Node_PubKey.decode(), curve)
    Shared_Key = TA_PrivKey_INT * RSU_PubKey_Point
    Shared_Key_256 = ecc_point_to_256_bit_key(Shared_Key)
    return binascii.hexlify(Shared_Key_256).decode()

def save_rsu_data_transfer(sid, psid, authtoken, authtokenSig):
    conn = sqlite3.connect("./DataBases/TAdb.db")
    cursor = conn.cursor()
    query = "INSERT INTO R_Data_Transfer (SID, PSID, AuthToken, AuthTokenSig) VALUES (?,?,?,?)"
    cursor.execute(query, (sid, psid, authtoken, authtokenSig))
    conn.commit()
    conn.close()
    print("RSU Data Transfer Details Stored in Database")

def extract_ta_credentials():
    ta_credentials = {
        "TA_Pub_Key": None,
        "TA_Priv_Key": None,
    }
    conn = sqlite3.connect("./DataBases/TAdb.db")
    cursor = conn.cursor()
    query = "SELECT * FROM TA_Keys"
    cursor.execute(query)
    results = cursor.fetchone()
    ta_credentials['TA_Pub_Key'] = results[0]
    ta_credentials['TA_Priv_Key'] = results[1]
    return ta_credentials

def extract_rsu_credentials(RSU_SID):
    rsu_credentials = {
        "RSU_SID": None,
        "RSU_Challenge": None,
        "RSU_Pub_Key": None
    }
    conn = sqlite3.connect("./DataBases/TAdb.db")
    cursor = conn.cursor()
    query = "SELECT * FROM R_Data WHERE SID =?"
    cursor.execute(query, (RSU_SID,))
    results = cursor.fetchone()
    if results == None:
        return rsu_credentials
    rsu_credentials['RSU_SID'] = results[0]
    rsu_credentials['RSU_Challenge'] = results[1]
    rsu_credentials['RSU_Pub_Key'] = results[2]
    return rsu_credentials

def extract_v_credentials(RSU_SID):
    v_credentials = {
        "V_SID": None,
        "V_Challenge": None,
        "V_Pub_Key": None
    }
    conn = sqlite3.connect("./DataBases/TAdb.db")
    cursor = conn.cursor()
    query = "SELECT * FROM V_Data WHERE SID =?"
    cursor.execute(query, (RSU_SID,))
    results = cursor.fetchone()
    v_credentials['V_SID'] = results[0]
    v_credentials['V_Challenge'] = results[1]
    v_credentials['V_Pub_Key'] = results[2]
    return v_credentials

def create_signature(msg, priv_key):
    privkey = int(priv_key)
    hash_msg = hashlib.sha256(msg.encode('utf-8')).digest()
    z = int.from_bytes(hash_msg, 'big')
    k = secrets.randbelow(curve.field.n)
    r = (k * curve.g).x % curve.field.n
    s = ((z + r * privkey) * pow(k, -1, curve.field.n)) % curve.field.n
    # Convert r and s to hexadecimal and concatenate them
    signature = f"{r:064x}{s:064x}"
    return signature

def decompress_point(hex_point, curve=curve):
    x_hex = hex_point[:-1]
    y_parity = int(hex_point[-1])
    x = int(x_hex, 16)
    rhs = (x ** 3 + curve.a * x + curve.b) % curve.field.p
    y = pow(rhs, (curve.field.p + 1) // 4, curve.field.p)
    if y % 2 != y_parity:
        y = curve.field.p - y
    return Point(curve, x, y)

def ecc_point_to_256_bit_key(point):
    x_bytes = point.x.to_bytes((point.x.bit_length() + 7) // 8, byteorder='big')
    y_bytes = point.y.to_bytes((point.y.bit_length() + 7) // 8, byteorder='big')

    sha = hashlib.sha256()
    sha.update(x_bytes)
    sha.update(y_bytes)
    return sha.digest()

def generate_nonce_and_response(challenge):
    N1 = os.urandom(16).hex()
    rsu_res = hashlib.sha256((N1 + challenge).encode()).hexdigest()
    return N1, rsu_res

def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def encrypt_message(message, sharedkey):
    shared_key = binascii.unhexlify(sharedkey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(message.encode(), shared_key)
    return ciphertext,nonce,authTag

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def decrypt_message(msg, sharedkey):
    shared_key = binascii.unhexlify(sharedkey)
    ciphertext = bytes.fromhex(msg['ciphertext'])
    nonce = bytes.fromhex(msg['nonce'])
    authTag = bytes.fromhex(msg['authTag'])
    plaintext_message = decrypt_AES_GCM(ciphertext, nonce,authTag, shared_key)
    end_time = time.perf_counter()
    return plaintext_message

def verify_signature(msg, signature, compressed_pub_key):
    pub_key_point = decompress_point(compressed_pub_key)
    hash_msg = hashlib.sha256(msg.encode('utf-8')).digest()
    z = int.from_bytes(hash_msg, 'big')
    # Split the signature string back into r and s
    r = int(signature[:64], 16)
    s = int(signature[64:], 16)
    w = pow(s, -1, curve.field.n)
    u1 = (z * w) % curve.field.n
    u2 = (r * w) % curve.field.n
    v = (u1 * curve.g + u2 * pub_key_point).x % curve.field.n
    return v == r
