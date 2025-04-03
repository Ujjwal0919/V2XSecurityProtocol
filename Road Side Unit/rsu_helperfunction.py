import binascii
import os
import re, hashlib
import secrets
import sqlite3
import sys

from ecdsa import SigningKey, VerifyingKey, BRAINPOOLP256r1, ellipticcurve
from tinyec import registry
from tinyec.ec import Point
from Crypto.Cipher import AES

#curve = registry.get_curve('BRAINPOOLP160r1') # 160 Bit
#curve = registry.get_curve('BRAINPOOLP192r1')  # 192-bit (current)
curve = registry.get_curve('brainpoolP256r1') # 256-bit
#curve = registry.get_curve('BRAINPOOLP320r1')  # 320-bit
#curve = registry.get_curve('BRAINPOOLP512r1')  # 512-bit

def fetch_vehicle_cache(SID):
    conn = sqlite3.connect("./Database/rsu_db.db")
    cursor = conn.cursor()
    query = "SELECT Chall FROM vehicle_cache_data WHERE SID=?"
    cursor.execute(query, (SID,))
    result = cursor.fetchone()
    conn.close()
    if result is not None:
        return result[0]
    else:
        return None
def save_rsu_data_transfer(sid, authtoken, authtokenSig):
    with open('rsu_data_transfer.txt', 'w') as file:
        file.write(f"SID: {sid}\n")
        file.write(f"AuthToken: {authtoken}\n")
        file.write(f"AuthTokenSig: {authtokenSig}\n")
        print("RSU Data Transfer Details Stored in rsu_data_transfer.txt")

from Crypto.Cipher import AES

def generate_group_enc_key():
    aes_gcm_key = AES.new(32, AES.MODE_GCM)
    return aes_gcm_key

def save_vehicle_creds(SID, Chall):
    conn = sqlite3.connect("./Database/rsu_db.db")
    cursor = conn.cursor()
    query = "INSERT INTO vehicle_cache_data (SID, Chall) VALUES (?,?)"
    cursor.execute(query, (SID, Chall))
    conn.commit()
    conn.close()

def extract_keys_from_file():
    file_path = 'rsu_keys.txt'
    keys = {
        "SID": None,
        "Challenge": None,
        "RSU PrivKey": None,
        "RSU PubKey": None,
        "TA PubKey": None
    }
    with open(file_path, 'r') as file:
        content = file.read()
    keys["SID"] = re.search(r"SID:\s([a-f0-9]+)", content).group(1)
    keys["Challenge"] = re.search(r"Challenge:\s([a-f0-9]+)", content).group(1)
    keys["RSU PrivKey"] = re.search(r"RSU PrivKey:\s(\d+)", content).group(1)
    keys["RSU PubKey"] = re.search(r"RSU PubKey:\s(0x[a-f0-9]+)", content).group(1)
    keys["TA PubKey"] = re.search(r"TA PubKey:\s(0x[a-f0-9]+)", content).group(1)
    return keys

def generate_shareKey(RSU_PrivKey, PubKey):
    RSU_PrivKey_INT = int(RSU_PrivKey)
    PubKey_Point = decompress_point(PubKey)
    Shared_Key = RSU_PrivKey_INT * PubKey_Point
    Shared_Key_256 = ecc_point_to_256_bit_key(Shared_Key)
    return binascii.hexlify(Shared_Key_256).decode()

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
def decompress_ta_pubKey_signature(compressed_key):
    x_hex = compressed_key[:-1]  # All except the last digit is the x-coordinate
    y_parity = int(compressed_key[-1])  # Last digit represents the y-parity (even/odd)
    x = int(x_hex, 16)
    curve_obj = BRAINPOOLP256r1.curve
    p = curve_obj.p()
    y_squared = (x**3 + curve_obj.a() * x + curve_obj.b()) % p
    y = pow(y_squared, (p + 1) // 4, p)
    if y % 2 != y_parity:
        y = p - y
    return ellipticcurve.Point(curve_obj, x, y)

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

def generate_nonce_and_response(challenge):
    N1 = os.urandom(16).hex()
    rsu_res = hashlib.sha256((N1 + challenge).encode()).hexdigest()
    return N1, rsu_res

def decompress_point(hex_point, curve=curve):
    x_hex = hex_point[:-1]
    y_parity = int(hex_point[-1])
    x = int(x_hex, 16)
    rhs = (x ** 3 + curve.a * x + curve.b) % curve.field.p
    y = pow(rhs, (curve.field.p + 1) // 4, curve.field.p)
    if y % 2 != y_parity:
        y = curve.field.p - y
    return Point(curve, x, y)

def extract_rsu_data_transfer():
    file_path = 'rsu_data_transfer.txt'
    data = {
        "SID": None,
        "AuthToken": None,
        "AuthTokenSig": None
    }
    with open(file_path, 'r') as file:
        content = file.read()
    data["SID"] = re.search(r"SID:\s([a-f0-9]+)", content).group(1)
    data["AuthToken"] = re.search(r"AuthToken:\s([a-f0-9:TZ-]+)", content).group(1)
    data["AuthTokenSig"] = re.search(r"AuthTokenSig:\s([a-f0-9]+)", content).group(1)
    return data

def ecc_point_to_256_bit_key(point):
    x_bytes = point.x.to_bytes((point.x.bit_length() + 7) // 8, byteorder='big')
    y_bytes = point.y.to_bytes((point.y.bit_length() + 7) // 8, byteorder='big')

    sha = hashlib.sha256()
    sha.update(x_bytes)
    sha.update(y_bytes)
    return sha.digest()

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
    return plaintext_message

def get_packet_size(data_packet):
    total_size = 0
    for key, value in data_packet.items():
        total_size += sys.getsizeof(key)
        if key in ['ciphertext', 'nonce', 'authTag']:
            total_size += len(binascii.unhexlify(value))
        elif isinstance(value, str):
            total_size += len(value.encode('utf-8'))
        else:
            total_size += sys.getsizeof(value)
    total_size += sys.getsizeof(data_packet)
    return total_size