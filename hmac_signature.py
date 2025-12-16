import secrets
import hmac
import hashlib
import json

secret_key = secrets.token_bytes(32)
#print(secret_key)
#print(secret_key.hex())


def calc_hash(key, message ):
    payload = json.dumps(message, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return signature

def verify_hash(key, message, signature):
    payload = json.dumps(message, sort_keys=True, separators=(",", ":")).encode()
    calc_sign = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, calc_sign)

test_hash = calc_hash(secret_key, {"door": 105, "rfid_tag": "sdlk25"})
print(test_hash)
print(verify_hash((secret_key + "1".encode()), {"door": 105, "rfid_tag": "sdlk25"}, test_hash))