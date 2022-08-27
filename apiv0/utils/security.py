from flask import Blueprint
import requests
import os
import json
import time
import serial
from cryptography.fernet import Fernet

bp = Blueprint("security_utils", __name__)

class Security:
    def __init__(self, meower, request):
        self.meower = meower
        self.request = request

        # Init encryption
        self._init_encryption()

        # Ratelimits
        self.last_packet = {}
        self.burst_amount = {}
        self.ratelimits = {}

        # Add functions to Meower class
        self.meower.encrypt = self.encrypt
        self.meower.decrypt = self.decrypt
        self.meower.ratelimit = self.ratelimit
        self.meower.check_ratelimit = self.check_ratelimit
        self.meower.check_captcha = self.check_captcha

    def _init_encryption(self):
        # Init variables
        self.encryption_key = None
        self.encryption = None

        if os.environ["ENCRYPTION_KEY_FROM"] == "env": # Get encryption key from env (less secure)
            self.encryption_key = os.environ["ENCRYPTION_KEY"]
        elif os.environ["ENCRYPTION_KEY_FROM"] == "meowkey": # Get encryption key from USB UART device (more secure)
            self.meower.meowkey = self.EasyUART(os.environ["MEOWKEY_PORT"])
            self.meower.meowkey.connect()
            self.meower.meowkey.rx()
            self.meower.meowkey.tx(json.dumps({"cmd": "ACK?"}))
            signal = json.loads(self.meower.meowkey.rx())
            if signal["cmd"] == "ACK!":
                self.meower.meowkey.tx(json.dumps({"cmd": "KEY?"}))
                payload = json.loads(self.meower.meowkey.rx())
                if payload["cmd"] == "KEY!":
                    self.encryption_key = payload["key"].encode()
                else:
                    self.log("MeowKey refused to send encryption key")
        
        # Set Fernet class
        if self.encryption_key is None:
            self.log("Failed to initialize encryption -- Please make sure the encryption key is correct")
            exit()

    def _stop_on_meowkey_disconnect(self):
        # Wait until MeowKey disconnects
        while self.meowkey.bus.connected:
            pass
        
        # Disconnected from MeowKey, destroy encryption key in memory
        self.encryption_key = None
        self.meowkey = None
        self.meower.log("Disconnected from MeowKey")
        exit()

    def encrypt(self, uid, data):
        encryption_info = self.meower.db.encryption_keys.find_one({"_id": uid})
        if encryption_info is None:
            # Generate encryption key
            key = Fernet.generate_key()
            encrypted_key = Fernet(self.encryption_key).encrypt(key)
            self.meower.db.encryption_keys.insert_one({"_id": uid, "key": encrypted_key})
        else:
            # Set current encryption key
            key = Fernet(self.encryption_key).decrypt(encryption_info["key"])

        # Encrypt data
        encrypted_data = Fernet(key).encrypt(data.encode())

        return encrypted_data

    def decrypt(self, uid, data):
        encryption_info = self.meower.db.encryption_keys.find_one({"_id": uid})
        if encryption_info is None:
            # Encryption key doesn't exist
            raise Exception
        else:
            # Set current encryption key
            key = Fernet(self.encryption_key).decrypt(encryption_info["key"])

        # Decrypt data
        decrypted_data = Fernet(key).decrypt(data.encode()).decode()
        return decrypted_data

    def ratelimit(self, type, client, burst=1, seconds=1):
        # Check if type and client are in ratelimit dictionary
        if not (type in self.last_packet):
            self.last_packet[type] = {}
            self.burst_amount[type] = {}
            self.ratelimits[type] = {}
        if client not in self.last_packet[type]:
            self.last_packet[type][client] = 0
            self.burst_amount[type][client] = 0
            self.ratelimits[type][client] = 0

        # Check if max burst has expired
        if (self.last_packet[type][client] + (seconds * 1000)) < self.meower.time():
            self.burst_amount[type][client] = 0

        # Set last packet time and add to burst amount
        self.last_packet[type][client] = self.meower.time()
        self.burst_amount[type][client] += 1

        # Check if burst amount is over max burst
        if self.burst_amount[type][client] >= burst:
            self.ratelimits[type][client] = (self.meower.time() + (seconds * 1000))
            self.burst_amount[type][client] = 0

    def check_ratelimit(self, type, client):
        # Check if type and client are in ratelimit dictionary
        if not (type in self.ratelimits):
            self.ratelimits[type] = {}
        if client not in self.ratelimits[type]:
            self.ratelimits[type][client] = 0

        # Check if user is currently ratelimited
        if self.ratelimits[type][client] > self.meower.time():
            return self.resp(106, {"expires": self.ratelimits[type][client]}, abort=True)

    def check_captcha(self, captcha):
        # Check if captcha is valid
        captcha_resp = requests.post("https://hcaptcha.com/siteverify", data={"response": captcha, "secret": os.getenv("HCAPTCHA_SECRET")}).json()
        return captcha_resp["success"]

class EasyUART:
    def __init__(self, port):
        self.bus = serial.Serial(port = port, baudrate = 9600)

    def connect(self): # This code is platform specific
        if not self.bus.connected:
            while not self.bus.connected:
                time.sleep(1)
        self.bus.reset_input_buffer()
        return True
    
    def tx(self, payload): # Leave encoding as ASCII since literally everything supports it
        self.bus.write(bytes(payload + "\r", "ASCII"))
    
    def rx(self):
        done = False
        tmp = ""
        while not done:
            # Listen for new data
            if self.bus.in_waiting != 0:
                readin = self.bus.read(self.bus.in_waiting).decode("ASCII")
                
                for thing in readin:
                    if thing == "\r":
                        done = True
                    else:
                        tmp += thing
        return tmp