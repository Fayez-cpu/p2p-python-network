from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def get_dh_keys():
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key,public_key


def get_kdf_key(key):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32, 
            salt=None,      
            info=b"aes key",
        ).derive(key)