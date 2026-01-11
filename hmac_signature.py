import secrets
import hmac
import hashlib
import json


secret_key = secrets.token_bytes(32)
#rint(secret_key)
#print(secret_key.hex())
print(hashlib.sha256("Shkyeyr!wtl76gG".encode() + "Clfcb7a1!wt".encode()).hexdigest())

def calc_hash(key, payload ):
    signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return signature

def verify_hash(key, payload_bytes, signature_hex):
    calc_sign = hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature_hex, calc_sign)


