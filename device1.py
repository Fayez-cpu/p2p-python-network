
import socket
import threading
import json
import hmac_signature
import os
import hmac
import hashlib
import hmac_signature
import datetime

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from crypto.dh import get_dh_keys, get_kdf_key
from crypto.aes import encrypt_message
from crypto.hmac import sign_message

hmac_key = b"2'\xae\x14\xbe\xb0\x0e\x88\xb4\xf6m\x10iL2\x0f\x85C\xfe\xa9\x16\xd5(H\x8aA*\xcf\r$\x1e\xf1"


class Device:
    def __init__(self, discovery_port, tcp_port, buffer_size):
        self.discovery_port = discovery_port
        self.tcp_port = tcp_port
        self.buffer_size = buffer_size


    def encrypt_hash_message(self, plaintext): 
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor() 
        ciphertext = encryptor.update(plaintext) + encryptor.finalize() 
        return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex(), "hmac": hmac_signature.calc_hash(hmac_key, ciphertext)}

    def verify_decrypt_message(self,message):
        ciphertext = bytes.fromhex(message["ciphertext"])
        if not hmac_signature.verify_hash(hmac_key, ciphertext, message["hmac"]):
            print("hmac error")
            return False
        nonce = bytes.fromhex(message["nonce"])
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = plaintext.decode()
        print(f"plaintext is {plaintext}")
        plaintext_data = json.loads(plaintext)
        now = int(datetime.datetime.now().timestamp())
        if abs(now - plaintext_data["timestamp"]) > 4:
            print("timestamp error")
            return False
        if plaintext_data["nonce"] in self.nonces:
            print("nonce error")
            return False
        else:
            self.add_nonce(plaintext_data["nonce"])
        return plaintext_data



    def run_tcp_server(self):
        listening_tcp_server = threading.Thread(target=self.start_tcp_server)
        listening_tcp_server.start()
    def start_discovery_listener_server(self):
        # start udp socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", self.discovery_port))
        print(f"[UDP] Discovery listener on port {self.discovery_port}")
        print("text".encode())
        while True:
            data, addr = sock.recvfrom(self.buffer_size)
            #receives a connetiom
            try:
                msg = json.loads(data.decode())
            except json.JSONDecodeError:
                print("[UDP] Received non-JSON data, ignoring")
                continue

            print(f"[UDP] Received from {addr}: {msg}")
            

            if msg.get("msg_type") == "DISCOVER":
                # Prepare response with info needed to connect over TCP
                response = {
                    "msg_type": "DISCOVER_RESPONSE",
                    "id": self.device_id,
                    "device_type": self.device_type, 
                    "tcp_port": self.tcp_port
                }
                
                sock.sendto(json.dumps(response).encode(), addr)
                print(f"[UDP] Sent DISCOVER_RESPONSE to {addr}")



    def discover_peers(self, my_id, my_type):
        # send a udp broadcast to all devices on the network
        # this is used by door sensor
        DISCOVERY_TIMEOUT = 5
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(DISCOVERY_TIMEOUT)

        discovery_msg = {
            "msg_type": "DISCOVER",
            "id": my_id,
            "device_type": my_type
        }

        # Broadcast on the local network
        sock.sendto(json.dumps(discovery_msg).encode(), ("<broadcast>", 5001 ))
        print("[UDP] Discovery broadcast sent")
        
        discovered = []

        
        while True:
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                print("[UDP] Discovery timeout reached")
                break

            try:
                msg = json.loads(data.decode())
            except json.JSONDecodeError:
                continue

            if msg.get("msg_type") == "DISCOVER_RESPONSE":
                print(f"[UDP] Got response from {addr}: {msg}")
                discovered.append({
                    "id": msg.get("id"),
                    "device_type": msg.get("device_type"),
                    "ip": addr[0],
                    "tcp_port": msg.get("tcp_port")
                })
            self.send_tcp_connection(addr[0], 5005)



        sock.close()
        return discovered  
    
    def start_tcp_server(self):
        # server is the tcp socket created
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0',5005))
        server.listen()
        while True:
            connection, address = server.accept()
            print(f"Connected by {address}")
            #print(connection)
            connection_thread = threading.Thread(target=self.handle_connection_server, args=(connection,))
            connection_thread.start()


    def handle_connection_server(self, connection):
        self.tcp_conn = connection
        key = self.recv_tcp_message(connection)
        if key != self.secret_key:
            print("Incorrect secret key! Terminating Connection")
            self.connection.close()
        private_key, public_key = get_dh_keys()
        peer_public_key = self.recv_tcp_message(connection)
        public_bytes = public_key.public_bytes( encoding=serialization.Encoding.Raw,
                                       format=serialization.PublicFormat.Raw)
        self.send_tcp_message(public_bytes.hex())
        peer_public_bytes = bytes.fromhex(peer_public_key)
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = private_key.exchange(peer_public_key)
        print(shared_secret)
        self.aes_key = get_kdf_key(shared_secret)
        while True:
            try:
                message = self.recv_tcp_message(connection)
                print("message is")
                print(message)
                decrypted = self.verify_decrypt_message(message)
                if not decrypted:
                    self.send_tcp_message("Invalid hash/timepstampy")
                    return "Invalid hash"
                entry = self.check_entry(decrypted)
                self.send_tcp_message(entry)
            except Exception as e:
                print(f"{e} Error, closing connection {connection}")
                break

    def send_tcp_connection(self, ip, port):
        #door sensor tcp connection
        self.tcp_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_conn.connect((ip, port))
        connection = self.tcp_conn
        self.send_tcp_message(self.secret_key)
        print("Connected")
        private_key, public_key = get_dh_keys()
        public_bytes = public_key.public_bytes( encoding=serialization.Encoding.Raw,
                                       format=serialization.PublicFormat.Raw)
        self.send_tcp_message(public_bytes.hex())
        peer_public_key = self.recv_tcp_message(connection)
        peer_public_bytes = bytes.fromhex(peer_public_key)
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = private_key.exchange(peer_public_key)
        self.aes_key = get_kdf_key(shared_secret)

    def timestamp_jsonby(self,message):
        message["timestamp"] = int(datetime.datetime.now().timestamp())
        message = json.dumps(message)
        return message.encode()


    def send_message(self,message):
        plaintext = json.dumps(message).encode()
        encrypted = encrypt_message(self.aes_key, plaintext)
        print(f"encrypted message is {encrypted}")
        encrypted["hmac"] = sign_message(hmac_key, encrypted["ciphertext"])
        self.send_tcp_message(encrypted)

    def send_tcp_message(self, message):
        message = json.dumps(message)
        self.tcp_conn.send(message.encode())



    def recv_tcp_message(self, connection):
            message = json.loads(connection.recv(1024).decode())
            return message
