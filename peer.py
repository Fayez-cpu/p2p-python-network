# broadcast message

#listen for connection - socket.bind()

# connect to another device - socket.connect()

import time
import threading
import socket
import json

DISCOVERY_PORT = 5001      # UDP port for discovery
TCP_PORT = 5000            # Your existing TCP server port
BUFFER_SIZE = 1024

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def start_discovery_listener(device_id, device_type):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Allow reuse of the address
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", DISCOVERY_PORT))

    print(f"[UDP] Discovery listener on port {DISCOVERY_PORT}")

    while True:
        data, addr = sock.recvfrom(BUFFER_SIZE)
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
                "id": device_id,
                "device_type": device_type,
                "ip": get_local_ip(),
                "tcp_port": TCP_PORT
            }
            sock.sendto(json.dumps(response).encode(), addr)
            print(f"[UDP] Sent DISCOVER_RESPONSE to {addr}")

def discover_peers(my_id, my_type):

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)


    discovery_msg = {
        "msg_type": "DISCOVER",
        "id": my_id,
        "device_type": my_type
    }

    # Broadcast on the local network
    sock.sendto(json.dumps(discovery_msg).encode(), ("<broadcast>", DISCOVERY_PORT))
    print("[UDP] Discovery broadcast sent")
    get_tcp_connection()

    discovered = []


    while True:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
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


        # Optional extra timeout control


    sock.close()
    return discovered

def get_tcp_connection():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0',TCP_PORT))
    server.listen()
    client, address = server.accept()
    print(f"Connected by {address}")
    receive_thread = threading.Thread(target=get_tcp_message, args=(client,))
    receive_thread.start()

    send_thread = threading.Thread(target=send_tcp_message, args=(client,))
    send_thread.start()

def send_tcp_message(conn):
    while True:
        message = input("")
        conn.send(message.encode())

def get_tcp_message(conn):
    while True:
        try:
            message = conn.recv(1024).decode()
            print(message)
        except:
            print("Error")


discover_peers("1007", "camera")

