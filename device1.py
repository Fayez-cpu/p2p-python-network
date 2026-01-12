
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
from crypto.aes import encrypt_message, decrypt_message
from crypto.hmac import sign_message, verify_hash, check_timestamp

hmac_key = b"2'\xae\x14\xbe\xb0\x0e\x88\xb4\xf6m\x10iL2\x0f\x85C\xfe\xa9\x16\xd5(H\x8aA*\xcf\r$\x1e\xf1"


class Device:
    def __init__(self, discovery_port, tcp_port, buffer_size):
        self.discovery_port = discovery_port
        self.tcp_port = tcp_port
        self.buffer_size = buffer_size
        self.peers = []
        self.nonce_list = []


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
        if plaintext_data["nonce"] in self.nonce_list:
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
            self.peers.append({"id": msg["id"], "connection": None, "aes_key": None})

            if msg["msg_type"] == "DISCOVER":
                # Prepare response with info needed to connect over TCP
                response = {
                    "msg_type": "DISCOVER_RESPONSE",
                    "id": self.device_id,
                    "tcp_port": self.tcp_port
                }
                
                sock.sendto(json.dumps(response).encode(), addr)
                print(f"[UDP] Sent DISCOVER_RESPONSE to {addr}")



    def discover_peers(self):
        # send a udp broadcast to all devices on the network
        # this is used by door sensor
        DISCOVERY_TIMEOUT = 5
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(DISCOVERY_TIMEOUT)

        discovery_msg = {
            "msg_type": "DISCOVER",
            "id": self.id
        }

        # Broadcast on the local network
        sock.sendto(json.dumps(discovery_msg).encode(), ("<broadcast>", 5001 ))
        print("[UDP] Discovery broadcast sent")
        


        
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
                tcp_port = msg["tcp_port"]
                self.peers.append({
                    "id": msg["id"],
                    "ip": addr[0],
                    "tcp_port": tcp_port
                })
            self.send_tcp_connection(addr[0], tcp_port)



        sock.close()

    def get_connection():
        pass
    
    def start_tcp_server(self):
        # server is the tcp socket created
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0',5005))
        server.listen()
        while True:
            connection, address = server.accept()
            print(f"Connected by {address}")
            for peer in self.peers:
                if not peer["connection"]:
                    peer["connection"] = connection
            #print(connection)
            connection_thread = threading.Thread(target=self.handle_connection_server, args=(connection,))
            connection_thread.start()


    def handle_connection_server(self, connection):
        self.tcp_conn = connection
        
        #self.connection.close()
        private_key, public_key = get_dh_keys()
        peer_public_key = self.recv_tcp_message(connection)
        public_bytes = public_key.public_bytes( encoding=serialization.Encoding.Raw,
                                       format=serialization.PublicFormat.Raw)
        self.send_tcp_message(public_bytes.hex(), connection)
        peer_public_bytes = bytes.fromhex(peer_public_key)
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = private_key.exchange(peer_public_key)
        print(shared_secret)
        aes_key = get_kdf_key(shared_secret)
        while True:
            try:
                received = self.recv_message(connection, aes_key)
                print(f"received message is {received}")
                print(received[0])
                if not received[0]:
                    print("Error ")
                    return received[1]
                else:
                    message = received[1]
                    print("message is")
                    print(message)
                    entry = self.check_entry(message)
                    self.send_message(entry, aes_key, connection)
            except Exception as e:
                print(f"{e} Error decrypting message")
                self.send_message("Error decrypting", aes_key, connection)
                connection.close()

    def send_tcp_connection(self, ip, port):
        #door sensor tcp connection
        self.tcp_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_conn.connect((ip, port))
        connection = self.tcp_conn

        print("Connected")
        private_key, public_key = get_dh_keys()
        public_bytes = public_key.public_bytes( encoding=serialization.Encoding.Raw,
                                       format=serialization.PublicFormat.Raw)
        self.send_tcp_message(public_bytes.hex(), connection)
        peer_public_key = self.recv_tcp_message(connection)
        peer_public_bytes = bytes.fromhex(peer_public_key)
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = private_key.exchange(peer_public_key)
        self.aes_key = get_kdf_key(shared_secret)




    def send_message(self,message, aes_key, connection):
        plaintext = json.dumps(message).encode()
        encrypted = encrypt_message(aes_key, plaintext)
        print(f"encrypted message is {encrypted}")
        encrypted["hmac"] = sign_message(hmac_key, encrypted["ciphertext"])
        self.send_tcp_message(encrypted, connection)

    def send_tcp_message(self, message, connection):
        message = json.dumps(message)
        connection.send(message.encode())

    def recv_message(self, connection, aes_key):
        encrypted = self.recv_tcp_message(connection)
        if not verify_hash(hmac_key, encrypted):
            connection.close()
            return [False, "Invalid signature"]
        plaintext = decrypt_message(aes_key, encrypted)
        print(f"plaintext is {plaintext}")
        if not check_timestamp(plaintext, self.nonce_list):
            return [False, "Invalid/old timestamp"]
        return [True, plaintext]

    def recv_tcp_message(self, connection):
            message = json.loads(connection.recv(1024).decode())
            return message
