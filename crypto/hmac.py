
import hmac
import hashlib
import datetime



def sign_message(key, payload ):
    payload = bytes.fromhex(payload)
    signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return signature

def verify_hash(key, payload):
    ciphertext = bytes.fromhex(payload["ciphertext"])
    signature = payload["hmac"]
    calc_sign = hmac.new(key, ciphertext, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, calc_sign)


def check_timestamp(plaintext, nonce_list):
        now = int(datetime.datetime.now().timestamp())
        if abs(now - plaintext["timestamp"]) > 4:
            print("timestamp error")
            return False
        if plaintext["nonce"] in nonce_list:
            print("nonce error")
            return False
        else:
            add_nonce(nonce_list, plaintext["nonce"])
        return True

def add_nonce(nonce_list, nonce):
        if len(nonce_list) >= 5:
            nonce_list.pop(0)
        nonce_list.append(nonce)