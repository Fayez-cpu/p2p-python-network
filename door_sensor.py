import json
from device1 import Device


class Door_sensor(Device):
    def __init__(self, device_id):
        self.id = device_id
        self.type = "door_sensor"
        self.peers = []
        self.authorized_tags = []
        self.state = "closed"
    
    def check_door_open(self, rfid_tag=None):
        if self.state == "open":
            return None
        self.state = "open"
        if rfid_tag in self.authorized_tags:
            access = "authorized"
        else:
            access = "unauthorized"
        message = {
            "msg_type": "door_open",
            "device_id": self.id,
            "door_state": "open",
            "access_type": access,
            "rfid_tag": rfid_tag
        }
        return message

    def check_door_closed(self):
        if self.state == "closed":
            return None
        self.state = "closed"
        

door_sensor = Door_sensor("front_door_#51572AB")
door_sensor.discover_peers( "105","door_sensor1")
while True:
    action = input("Type scan for RFID scan, force for forced entry, close for closing door: ") 
    if action == "scan":
        tag = input("Enter RFID tag")
        event = door_sensor.check_door_open(tag)
    elif action == "force":
        event = door_sensor.check_door_open()
    elif action == "close":
        event = door_sensor.check_door_closed()
    else:
        print("Unknown commad")
    
    if event:
        print(event)
        door_sensor.send_tcp_message(event)

