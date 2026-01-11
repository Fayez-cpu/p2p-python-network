from device1 import Device
import json
import hmac_signature
import datetime
import key_hashing

hmac_key = b"2'\xae\x14\xbe\xb0\x0e\x88\xb4\xf6m\x10iL2\x0f\x85C\xfe\xa9\x16\xd5(H\x8aA*\xcf\r$\x1e\xf1"


class Alarm(Device):
    def __init__(self, discovery_port, tcp_port, buffer_size, device_id):
        self.device_id = device_id
        self.device_type = "alarm"
        self.peers = []
        self.secret_key = "A5cf1hglf3!xgf"
        self.state = "idle"
        self.nonces = []
        super().__init__(discovery_port,tcp_port, buffer_size)

        
    def check_entry(self, message):
        if isinstance(message, str):
            message = json.loads(message)
        print(message)
        

        if not key_hashing.check_rfid(message["rfid_tag"]):
            self.state = "sound alarm"
            print(self.state)
            return "invalid tag"
        
        elif key_hashing.check_rfid(message["rfid_tag"]):
            self.state = "verified entry"
            print(self.state)
            return "valid tag"
        
    def add_nonce(self, nonce):
        if len(self.nonces) >= 5:
            self.nonces.pop(0)
        self.nonces.append(nonce)

        
alarm = Alarm(5001, 5000, 1024,"front_01")
 #alarm.check_entry({'msg_type': 'door_open', 'device_id': 'front_door_#51572AB', 'door_state': 'open', 'access_type': 'unauthorized', 'rfid_tag': None})
 # this above line is to test alarm with test json data
alarm.run_tcp_server()
alarm.start_discovery_listener_server()
