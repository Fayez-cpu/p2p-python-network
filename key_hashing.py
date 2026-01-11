import json
import hashlib
import hmac

with open("keys.json", "r") as f:
    authorized_keys = json.load(f)
    for entry in authorized_keys["users"]:
        #print(entry["rfid_hash"])
        pass

def hash_rfid(rfid, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        rfid.encode(),
        salt.encode(),
        50_000
    ).hex()

print(hash_rfid("#Clfcb7a1!wg", "Shkyeyr!wtl76gG"))

def check_rfid(rfid):
    #print("rfid is " + rfid)
    rfid = rfid.strip()
    for entry in authorized_keys["users"]:
        if "salt" not in entry or "rfid_hash" not in entry:
            continue
        salt = entry["salt"]
        calculated = hash_rfid(rfid, salt)
        #print(f"calculated {calculated}  entry {entry["rfid_hash"]}")
        if hmac.compare_digest(entry["rfid_hash"], calculated):
            return True
    return False

print(check_rfid("#Clfcb7a1!wg"))
#Clfcb7a1!wg
