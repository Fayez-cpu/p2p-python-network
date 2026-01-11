
import hmac
import hashlib

def sign_message(key, payload ):
    signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return signature

def verify_hash(key, payload_bytes, signature_hex):
    calc_sign = hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature_hex, calc_sign)


