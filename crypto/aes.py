import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import json
import os
def encrypt_message(aes_key, plaintext):
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex()}


def decrypt_message(aes_key, message):
        nonce = bytes.fromhex(message["nonce"])
        ciphertext = bytes.fromhex(message["ciphertext"])
        print(ciphertext)
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        print(plaintext)
        plaintext = plaintext.decode()
        return json.loads(plaintext)

