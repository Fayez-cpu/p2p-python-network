from device1 import Device
import json
import hmac_signature
import datetime
import key_hashing
import os
import requests
hmac_key = b"2'\xae\x14\xbe\xb0\x0e\x88\xb4\xf6m\x10iL2\x0f\x85C\xfe\xa9\x16\xd5(H\x8aA*\xcf\r$\x1e\xf1"


class Alarm(Device):
    def __init__(self, discovery_port, tcp_port, buffer_size, device_id):
        self.device_id = device_id
        self.device_type = "alarm"
        self.secret_key = "A5cf1hglf3!xgf"
        self.state = "idle"
        super().__init__(discovery_port,tcp_port, buffer_size, )
    
    
    def log_event(self, event):
        with open("logs/events.jsonl", "a") as f:
            f.write(json.dumps(event) + "\n")
        

    def send_log(self, log):
        requests.post(
            "http://localhost:3000/api/logs",
            json=log,
            timeout=2
        )

    def check_entry(self, message):
        if isinstance(message, str):
            message = json.loads(message)
        print(message)
        timestamp = int(datetime.datetime.now().timestamp())

        if not key_hashing.check_rfid(message["rfid_tag"]):
            self.state = "sound alarm"
            print(self.state)
            event = {"timestamp": timestamp, "device_id": message["device_id"], "result": "Rejected", "reason": "RFID_WRONG" }
            try:
                self.send_log(event)
            except:
                print("error sending to api")
            self.log_event(event)
            return {"authorization": "invalid tag", "timestamp": int(datetime.datetime.now().timestamp()), "nonce": os.urandom(6).hex()}
        
        elif key_hashing.check_rfid(message["rfid_tag"]):
            self.state = "verified entry"
            print(self.state)
            event = {"timestamp": timestamp, "device_id": message["device_id"], "result": "Allowed", "reason": "RFID_OK"}
            try:
                self.send_log(event)
            except:
                print("Error sending to api")
            self.log_event(event)
            return  {"authorization": "valid tag", "timestamp": timestamp, "nonce": os.urandom(6).hex()}
        
    def add_nonce(self, nonce):
        if len(self.nonces) >= 5:
            self.nonces.pop(0)
        self.nonces.append(nonce)

        
alarm = Alarm(5001, 5005, 1024,"alarm")
 #alarm.check_entry({'msg_type': 'door_open', 'device_id': 'front_door_#51572AB', 'door_state': 'open', 'access_type': 'unauthorized', 'rfid_tag': None})
 # this above line is to test alarm with test json data
alarm.run_tcp_server()
alarm.start_discovery_listener_server()
