
import socket
import threading
import json
class Device:
    def __init__(self, discovery_port, tcp_port, buffer_size):
        self.discovery_port = discovery_port
        self.tcp_port = tcp_port
        self.buffer_size = buffer_size

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
            self.send_tcp_connection(addr[0], 5000)



        sock.close()
        return discovered  
    
    def start_tcp_server(self):
        # server is the tcp socket created
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0',5000))
        server.listen()
        while True:
            connection, address = server.accept()
            print(f"Connected by {address}")
            #print(connection)
            connection_thread = threading.Thread(target=self.handle_connection_server, args=(connection,))
            connection_thread.start()


    def handle_connection_server(self, connection):
        key = self.recv_tcp_message(connection)
        if key != self.secret_key:
            print("Incorrect secret key! Terminating Connection")
            self.connection.close()
        while True:
            try:
                message = self.recv_tcp_message(connection)
                self.check_entry(message)
            except Exception as e:
                print(f"{e} Error, closing connection {connection}")
                break
        #receive_thread = threading.Thread(target=self.recv_tcp_message, args=(client,))
        #receive_thread.start()

        #send_thread = threading.Thread(target=self.send_tcp_message, args=(client,))
        #send_thread.start()
    def send_tcp_connection(self, ip, port):
        self.tcp_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_conn.connect((ip, port))
        self.send_tcp_message(self.secret_key)
        print("Connected")
        #receive_thread = threading.Thread(target=self.recv_tcp_message, args=(conn,))
        #receive_thread.start()

        #send_thread = threading.Thread(target=self.send_tcp_message, args=(conn,))
        #send_thread.start()

    def send_tcp_message(self, message):
        message = json.dumps(message)
        self.tcp_conn.send(message.encode())

    def recv_tcp_message(self, connection):
            message = json.loads(connection.recv(1024).decode())
            return message
