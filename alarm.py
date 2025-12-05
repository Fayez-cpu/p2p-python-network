from device1 import Device
import json
class Alarm(Device):
    def __init__(self, discovery_port, tcp_port, buffer_size, device_id):
        self.device_id = device_id
        self.device_type = "alarm"
        self.peers = []
        self.secret_key = "A5cf1hglf3"
        self.state = "idle"
        super().__init__(discovery_port,tcp_port, buffer_size)

    def check_entry(self, message):
        if isinstance(message, str):
            message = json.loads(message)
        if message["msg_type"] == "door_open" and message["access_type"] == "unauthorized":
            self.state = "sound alarm"
            return  "trigger alarm"
        elif message["msg_type"] == "door_open" and message["access_type"] == "authorized":
            self.state = "idle"
            return "authorized entry"
        
alarm = Alarm(5001, 5000, 1024,"front_01")
alarm.check_entry({'msg_type': 'door_open', 'device_id': 'front_door_#51572AB', 'door_state': 'open', 'access_type': 'unauthorized', 'rfid_tag': None})
alarm.start_discovery_listener()