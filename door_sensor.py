import json
from device1 import Device
import datetime
import hmac_signature
import os

hmac_key = b"2'\xae\x14\xbe\xb0\x0e\x88\xb4\xf6m\x10iL2\x0f\x85C\xfe\xa9\x16\xd5(H\x8aA*\xcf\r$\x1e\xf1"

class Door_sensor(Device):
    def __init__(self, device_id):
        self.id = device_id
        self.type = "door_sensor"
        self.authorized_tags = []
        self.state = "closed"
        self.secret_key = "A5cf1hglf3!xgf"
        self.peers = []
        self.nonce_list = []

    def check_door_open(self, rfid_tag=None):
        if self.state == "open":
            return None
        self.state = "open"
        
        message = {
            "msg_type": "door_open",
            "device_id": self.id,
            "rfid_tag": rfid_tag,
            "nonce": os.urandom(6).hex(),
            "timestamp": int(datetime.datetime.now().timestamp())
            
        }

        return message

    def check_door_closed(self):
        if self.state == "closed":
            return None
        self.state = "closed"

    def add_authorized_tag(self, tag):
        # setter to append an authorized tag  
        self.authorized_tags.append(tag)
              

door_sensor = Door_sensor("front_door_5187")
door_sensor.discover_peers()
while True:
    action = input("Type scan for RFID scan, force for forced entry, close for closing door: ") 
    if action == "scan":
        tag = input("Enter RFID tag: ")
        event = door_sensor.check_door_open(tag)
    elif action == "force":
        event = door_sensor.check_door_open()
    elif action == "close":
        event = door_sensor.check_door_closed()
    else:
        print("Unknown commad")
    
    if event:
        print(f"event is {event}")
        door_sensor.check_door_closed()
        secured_event = door_sensor.send_message(event, door_sensor.aes_key, door_sensor.tcp_conn)
        print(secured_event)
        authorization = door_sensor.recv_message(door_sensor.tcp_conn, door_sensor.aes_key)[1]
        print(authorization["authorization"])
    