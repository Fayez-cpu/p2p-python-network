from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization


private_key = x25519.X25519PrivateKey.generate()
public_key = private_key.public_key()
public_bytes = public_key.public_bytes( encoding=serialization.Encoding.Raw,
                                       format=serialization.PublicFormat.Raw)
print(public_bytes)
peer_private_key = x25519.X25519PrivateKey.generate()
peer_public_key = peer_private_key.public_key()

shared_secret = private_key.exchange(peer_public_key)
peer_shared_secret = peer_private_key.exchange(public_key)

