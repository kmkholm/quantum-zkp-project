# -*- coding: utf-8 -*-
"""
Created on Sat Feb 15 03:03:10 2025

@author: kmkho
"""

# -*- coding: utf-8 -*-
"""
Created on Fri Feb 14 05:10:49 2025

@author: kmkho
"""

import asyncio
import threading
import os
import json
import hashlib
import secrets
import time
import logging
import psutil
import queue
import paho.mqtt.client as mqtt
from web3 import Web3
from eth_account import Account
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
from queue import Queue
from threading import Lock
from sympy import nextprime, isprime
from phe import paillier
import base64
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import tkinter as tk
from tkinter import ttk, messagebox
import time
import logging
import asyncio
from queue import Queue
from threading import Lock
import paho.mqtt.client as mqtt
# MQTT Configuration
MQTT_BROKER = "localhost"
MQTT_PORT = 1883
CLIENT_ID_PREFIX = "iot_device"
MQTT_TOPIC = "iot/devices"
import asyncio 
import threading 
import os 
import json 
import hashlib 
import secrets 
import time 
import logging 
import psutil 
import queue 
import paho.mqtt.client as mqtt 
from web3 import Web3 
from eth_account import Account 
from typing import Dict, List, Optional, Union, Any 
from dataclasses import dataclass, asdict 
from abc import ABC, abstractmethod 
from queue import Queue 
from threading import Lock 
from sympy import nextprime, isprime 
from phe import paillier 
import base64 
import tkinter as tk 
from tkinter import ttk, messagebox, filedialog 
import numpy as np 
 
import tkinter as tk
from tkinter import ttk
# Blockchain Configuration
BLOCKCHAIN_URL = "http://127.0.0.1:7545"
ACCOUNT_ADDRESS = '0x336417aC1A0BcB5513254EDb797225088dc88D97'
PRIVATE_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'
CONTRACT_ADDRESS = '0x80FBA4e11a461F73D823CA274F8B56218d50c84F'
CONTRACT_PATH = 'build/contracts/IoTQuantumZKPStorage.json'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)
logger = logging.getLogger(__name__)

# Performance measurement decorator
def measure_performance(func):
    """Performance measurement decorator"""
    def wrapper(self, *args, **kwargs):
        process = psutil.Process(os.getpid())
        start_time = time.perf_counter()
        start_cpu = sum(process.cpu_times()[:2])
        start_mem = process.memory_info().rss
        
        try:
            result = func(self, *args, **kwargs)
            
            end_time = time.perf_counter()
            end_cpu = sum(process.cpu_times()[:2])
            end_mem = process.memory_info().rss
            
            exec_time = (end_time - start_time) * 1000
            cpu_time = (end_cpu - start_cpu) * 1000
            mem_delta = (end_mem - start_mem) / 1024
            
            metrics = {
                'action': func.__name__,
                'exec_time': exec_time,
                'cpu_time': cpu_time,
                'mem_delta': mem_delta,
                'timestamp': time.strftime('%H:%M:%S')
            }
            
            if hasattr(self, 'performance_data'):
                self.performance_data.append(metrics)
            
            return result
            
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {str(e)}")
            raise
            
    return wrapper

class SchnorrZKP:
    """Schnorr Zero-Knowledge Proof implementation"""
    
    def __init__(self, p=None, q=None, g=None):
        if p is None or q is None or g is None:
            self.generate_params()
        else:
            self.p = p  # Prime modulus
            self.q = q  # Subgroup order
            self.g = g  # Generator
            
        self.x = None  # Private key
        self.y = None  # Public key
        self.k = None  # Random nonce
        self.hash_function = hashlib.sha256
    
    def generate_params(self):
        """Generate Schnorr group parameters"""
        # Generate suitable primes
        while True:
            q = secrets.randbits(255)
            p = 2 * q + 1
            if self._is_probable_prime(q) and self._is_probable_prime(p):
                self.p = p
                self.q = q
                break
        
        # Find generator
        self.g = self._find_generator()
    
    def _is_probable_prime(self, n: int, k: int = 128) -> bool:
        """Miller-Rabin primality test"""
        if n <= 3:
            return n > 1
        if n % 2 == 0:
            return False
        
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
            
        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
                
            for _ in range(r - 1):
                x = (x * x) % n
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    def _find_generator(self) -> int:
        """Find a generator for the subgroup"""
        for g in range(2, self.p):
            if pow(g, self.q, self.p) == 1:
                return g
        raise ValueError("Generator not found")
    
    def generate_keypair(self) -> tuple:
        """Generate private-public key pair"""
        self.x = secrets.randbelow(self.q)
        self.y = pow(self.g, self.x, self.p)
        return self.x, self.y
    
    def create_proof(self, message: bytes) -> tuple:
        """Create ZK proof"""
        if self.x is None:
            raise ValueError("Private key not set")
        
        k = secrets.randbelow(self.q)
        commitment = pow(self.g, k, self.p)
        
        h = self.hash_function()
        h.update(str(commitment).encode() + message)
        challenge = int(h.hexdigest(), 16) % self.q
        
        response = (k - self.x * challenge) % self.q
        
        return (commitment, challenge, response)
    
    def verify_proof(self, message: bytes, proof: tuple, y: int) -> bool:
        """Verify ZK proof"""
        commitment, challenge, response = proof
        
        h = self.hash_function()
        h.update(str(commitment).encode() + message)
        computed_challenge = int(h.hexdigest(), 16) % self.q
        
        if computed_challenge != challenge:
            return False
        
        lhs = pow(self.g, response, self.p)
        rhs = (commitment * pow(y, challenge, self.p)) % self.p
        return lhs == rhs



 
class SecurityModule: 
    def __init__(self): 
        
        
        
        self.sec =(0,0,0,0) 
        self.integrity = True 
        self.device_keys = {} 
        self.homomorphic_enc = None 
        try: 
            self.init_homomorphic_encryption() 
        except Exception as e: 
            logger.error(f"SecurityModule failed to initialize: {str(e)}") 
            raise 
 
    def init_homomorphic_encryption(self): 
        try: 
            public_key, private_key = paillier.generate_paillier_keypair() 
            self.homomorphic_enc = { 
                'public_key': public_key, 
                'private_key': private_key 
            } 
        except Exception as e: 
            logger.error(f"Homomorphic encryption init error: {str(e)}") 
            raise 
 
    def generate_device_keys(self, device_id: str) -> tuple: 
        private_key = secrets.token_hex(32) 
        public_key = Web3.keccak(hexstr=private_key).hex() 
        self.device_keys[device_id] = { 
            'private_key': private_key, 
            'public_key': public_key, 
            'created_at': time.time() 
        } 
        return public_key, private_key 
 
    def encrypt_data(self, data: Union[str, bytes, int]) -> str: 
        try: 
            if isinstance(data, str): 
                data = int.from_bytes(data.encode(), 'big') 
            elif isinstance(data, bytes): 
                data = int.from_bytes(data, 'big') 
            encrypted = self.homomorphic_enc['public_key'].encrypt(data) 
            return base64.b64encode(str(encrypted.ciphertext()).encode()).decode() 
        except Exception as e: 
            logger.error(f"Encryption error: {str(e)}") 
            raise 
 
    def decrypt_data(self, encrypted_data: str) -> Union[str, int]: 
        try: 
            decoded = base64.b64decode(encrypted_data.encode()) 
            ciphertext = int(decoded.decode()) 
            encrypted_value = paillier.EncryptedNumber( 
                self.homomorphic_enc['public_key'], 
                ciphertext 
            ) 
            decrypted = self.homomorphic_enc['private_key'].decrypt(encrypted_value) 
            return decrypted 
        except Exception as e: 
            logger.error(f"Decryption error: {str(e)}") 
            raise 
 

            return None 
 
def verify_message(self, message: Dict[str, Any]) -> bool: 
    # Implement message verification logic 
    pass 
 
def update_progress(self, progress: int): 
    self.progress_ = progress 
 
def get_zcp_proof(self, peer: str) -> Dict[str, Any]: 
    # Implement ZCP proof generation logic 
    pass 
 
def compute_z_1(self): 
    # Implement Z1 computation logic 
    pass 
 
def compute_z_2(self, sA: str, sB: str, sC: str) -> Any: 
    # Implement Z2 computation logic 
    return None 
 
def verify_sC(self, sC: str) -> bool: 
    # Implement SC verification logic 
    return True 
 
def verify_z2_msg_1(self, data: List[str]) -> bool: 
    # Implement Z2 message verification logic 
    return True 
 
def verify_z2_msg_2(self, data: Dict[str, Any]) -> bool: 
    # Implement Z2 message verification logic 
    return True 
 

 
def send_share(self, share: Dict[str, Any]) -> None: 
    # Implement share sending logic 
    pass 
 
def run(self) -> None: 
    while True: 
        # Implement runtime logic for the SecurityModule 
        time.sleep(1) 



        
from dataclasses import dataclass

@dataclass
class IoTDeviceConfig:
    """IoT device configuration dataclass"""
    def __init__(self, device_id: str, device_type: str, owner_address: str, mqtt_topic: str):
        self.device_id = device_id
        self.device_type = device_type
        self.owner_address = owner_address
        self.mqtt_topic = mqtt_topic
        self.encryption_enabled = True
        self.batch_size = 100
        self.publish_interval = 1.0


class DeviceDataProcessor:
    """Process data from a specific IoT device"""
    
    def __init__(self, device_id: str, batch_size: int):
        self.device_id = device_id
        self.batch_size = batch_size
        self.current_batch = []
        self.sequence_tracker = {}
        self.last_processed = 0
        self.metric_data = {}
    
    async def process(self, data: dict):
        """Process incoming device data"""
        try:
            sequence = data.get('sequence', 0)
            
            if sequence <= self.last_processed:
                logger.warning(f"Out of order sequence: {sequence}")
                return
            
            if sequence > self.last_processed + 1:
                for missing in range(self.last_processed + 1, sequence):
                    self.sequence_tracker[missing] = time.time()
            
            self.last_processed = sequence
            
            processed_data = self._process_batch(data['data'])
            self.current_batch.extend(processed_data)
            
            # Store metric data for visualization
            for item in processed_data:
                if isinstance(item, dict):
                    for metric, value in item.items():
                        if metric not in self.metric_data:
                            self.metric_data[metric] = []
                        self.metric_data[metric].append(value)
            
            if len(self.current_batch) >= self.batch_size:
                await self._store_batch()
                
        except Exception as e:
            logger.error(f"Data processing error: {str(e)}")
    
    def _process_batch(self, batch_data: List[Any]) -> List[Any]:
        """Process batch of device data"""
        processed = []
        for item in batch_data:
            try:
                if isinstance(item, str) and item.isdigit():
                    processed.append(int(item))
                else:
                    processed.append(item)
            except Exception as e:
                logger.error(f"Item processing error: {str(e)}")
        return processed
    
    def get_metric_data(self, metric: str) -> List[float]:
        """Get stored metric data"""
        return self.metric_data.get(metric, [])
    
    async def _store_batch(self):
        """Store processed batch data"""
        try:
            batch_id = Web3.keccak(
                text=f"{self.device_id}-{time.time()}"
            ).hex()
            
            batch_data = {
                'batch_id': batch_id,
                'device_id': self.device_id,
                'timestamp': time.time(),
                'data': self.current_batch,
                'metadata': {
                    'sequence_range': [
                        min(self.sequence_tracker.keys()),
                        max(self.sequence_tracker.keys())
                    ] if self.sequence_tracker else []
                }
            }
            
            logger.info(f"Stored batch {batch_id} for device {self.device_id}")
            self.current_batch = []
            
        except Exception as e:
            logger.error(f"Batch storage error: {str(e)}")
            raise

class IoTDevice:
    def __init__(self, config: IoTDeviceConfig):
        self.config = config
        self.running = False
        self.is_active = False
        self.ctx_ = None 
        self.lock_ = threading.Lock() 
        self.data_queue = Queue()
        self.lock = asyncio.Lock()  # Use asyncio.Lock instead of threading.Lock
        self.batch = []
        self.sequence_number = 0
        self.last_seen = None
        # MQTT Client with updated version
        self.client = mqtt.Client(
           client_id=f"iot_device_{self.config.device_id}",
           protocol=mqtt.MQTTv5,
           callback_api_version=mqtt.CallbackAPIVersion.VERSION2
       )
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        
        # Initialize other components
        self.data_processor = DeviceDataProcessor(
            device_id=config.device_id,
            batch_size=config.batch_size
        )
        
        # Security setup
        self.security_module = None
        self.zkp = SchnorrZKP()
        self.private_key, self.public_key = self.zkp.generate_keypair()
        
        if self.config.encryption_enabled:
            self.setup_encryption()
            
        # Simulation settings
        self.simulate_data = True
        self.simulation_interval = 1.0
 

    def setup_encryption(self):
        """Initialize encryption using the SecurityModule"""
        self.security_module = SecurityModule()
        # Optional: Add any additional encryption setup here

    def setup_zkp(self):
        """Initialize Schnorr ZKP"""
        self.zkp = SchnorrZKP()
        self.private_key, self.public_key = self.zkp.generate_keypair()

    def generate_sensor_data(self):
        """Generate simulated sensor data"""
        data = {
            'temperature': round(20 + 5 * np.random.random(), 2),
            'humidity': round(50 + 10 * np.random.random(), 2),
            'pressure': round(1000 + 20 * np.random.random(), 2),
            'timestamp': time.time()
        }
        return data


    async def start(self):
        """Start device operation"""
        self.running = True
        try:
            self.client.connect(MQTT_BROKER, MQTT_PORT, 60, clean_start=True)
            self.client.loop_start()
            while self.running:
                if self.simulate_data:
                    data = self.generate_sensor_data()
                    if self.config.encryption_enabled:
                        data = {k: self.encrypt_data(str(v)) for k, v in data.items()}
                    await self._process_data_batch(data)
                await asyncio.sleep(self.simulation_interval)
        except Exception as e:
            logger.error(f"Device error: {str(e)}")
            self.stop()
    def stop(self):
        """Stop device operation"""
        self.running = False
        self.client.loop_stop()
        self.client.disconnect()

    def encrypt_data(self, data):
        """Encrypt data using the SecurityModule"""
        if self.security_module:
            return self.security_module.encrypt_data(data)
        else:
            raise RuntimeError("Encryption is not configured")

    def decrypt_data(self, encrypted_data):
        """Decrypt data using the SecurityModule"""
        if self.security_module:
            return self.security_module.decrypt_data(encrypted_data)
        else:
            raise RuntimeError("Encryption is not configured")

    async def _process_data_batch(self, data):
        """Process and publish data batch"""
        async with self.lock:
            if len(self.batch) >= self.config.batch_size:
                try:
                    batch_data = {
                        'device_id': self.config.device_id,
                        'timestamp': time.time(),
                        'sequence': self.sequence_number,
                        'data': self.batch
                    }

                    # Encrypt the batch if encryption is enabled
                    if self.config.encryption_enabled:
                        batch_data = await self._encrypt_batch(batch_data)

                    # Create ZKP proof for the batch
                    batch_data['proof'] = self.zkp.create_proof(str(self.batch).encode())

                    # Publish the batch data
                    message = json.dumps(batch_data)
                    self.client.publish(self.config.mqtt_topic, message)

                    # Process the batch through the data processor
                    await self.data_processor.process({
                        'device_id': self.config.device_id,
                        'sequence': self.sequence_number,
                        'data': self.batch
                    })

                    self.sequence_number += 1
                    self.batch = []
                except Exception as e:
                    logger.error(f"Batch processing error: {str(e)}")

    async def _encrypt_batch(self, batch_data):
        """Encrypt batch data using Paillier encryption"""
        encrypted_data = []
        for item in batch_data['data']:
            encrypted_item = self.security_module.encrypt_data(str(item))
            encrypted_data.append(encrypted_item)
        batch_data['data'] = encrypted_data
        return batch_data

    def setup_encryption(self):
        """Initialize encryption using the SecurityModule"""
        self.security_module = SecurityModule()
        # Optional: Additional encryption setup logic

    def _on_connect(self, client, userdata, flags, rc, properties=None):
    
        if rc == 0:
            self.is_active = True
            self.client.subscribe(self.config.mqtt_topic)
            logger.info(f"Connected to {self.config.mqtt_topic}")
        else:
            logger.error(f"Connection failed with reason code {rc}")

    def _on_message(self, client, userdata, message):
    
        try:
           payload = json.loads(message.payload.decode())
           self.process_data(payload)
        except Exception as e:
            logger.error(f"Message processing error: {str(e)}")



    def _on_disconnect(self, client, userdata, reasonCode):
        """Handle MQTT disconnections"""
        self.is_active = False
        logger.warning(f"Disconnected from broker with reason code {reasonCode}")

    def process_data(self, data):
        """Process incoming data"""
        # Implement data processing logic here
        pass

 


    # Additional methods and properties would go here
        
class BlockchainManager:
    """Manage blockchain interactions"""
    
    def __init__(self):
        # Initialize Web3
        self.web3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_URL))
        self.account_address = ACCOUNT_ADDRESS
        self.private_key = PRIVATE_KEY
        
        # Load contract
        try:
            with open(CONTRACT_PATH, 'r') as f:
                contract_json = json.load(f)
                self.contract_abi = contract_json['abi']
                
            self.contract = self.web3.eth.contract(
                address=CONTRACT_ADDRESS,
                abi=self.contract_abi
            )
            
            # Setup account
            self.account = Account.from_key(self.private_key)
            self.web3.eth.default_account = self.account_address
            
            logger.info("Blockchain manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize blockchain: {str(e)}")
            raise
    
    def register_device(self, device_id: str, device_type: str, owner: str) -> str:
        """Register device on blockchain"""
        try:
            # Convert device ID to bytes32
            device_id_bytes = Web3.keccak(text=device_id)
            
            # Map device type to enum
            device_type_map = {
                'Sensor': 0,
                'Actuator': 1,
                'Gateway': 2,
                'Edge Device': 3,
                'Custom': 4
            }
            device_type_value = device_type_map.get(device_type, 4)
            
            # Prepare metadata
            metadata = json.dumps({
                'mqtt_topic': f"iot/device/{device_id}",
                'timestamp': int(time.time()),
                'type': device_type,
                'owner': owner
            })
            
            # Build transaction
            tx = self.contract.functions.registerDevice(
                device_id_bytes,
                device_type_value,
                owner,
                metadata
            ).build_transaction({
                'from': self.account_address,
                'nonce': self.web3.eth.get_transaction_count(self.account_address),
                'gas': 2000000,
                'gasPrice': self.web3.eth.gas_price
            })
            
            # Sign and send transaction
            signed_tx = self.web3.eth.account.sign_transaction(tx, self.private_key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            # Wait for receipt
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status != 1:
                raise Exception("Blockchain registration failed")
            
            logger.info(f"Device {device_id} registered on blockchain. TX: {tx_hash.hex()}")
            return tx_hash.hex()
            
        except Exception as e:
            logger.error(f"Blockchain registration error: {str(e)}")
            raise
    
    def activate_device(self, device_id: str) -> str:
        """Activate device on blockchain"""
        try:
            device_id_bytes = Web3.keccak(text=device_id)
            
            tx = self.contract.functions.activateDevice(device_id_bytes).build_transaction({
                'from': self.account_address,
                'nonce': self.web3.eth.get_transaction_count(self.account_address),
                'gas': 200000,
                'gasPrice': self.web3.eth.gas_price
            })
            
            signed_tx = self.web3.eth.account.sign_transaction(tx, self.private_key)
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt.status != 1:
                raise Exception("Device activation failed")
            
            return tx_hash.hex()
            
        except Exception as e:
            logger.error(f"Device activation error: {str(e)}")
            raise
            
    def verify_device(self, device_id: str) -> bool:
        """Verify device exists on blockchain"""
        try:
            device_id_bytes = Web3.keccak(text=device_id)
            details = self.contract.functions.getDeviceDetails(device_id_bytes).call()
            return bool(details[1])  # Check registration time
        except Exception as e:
            logger.error(f"Device verification error: {str(e)}")
            return False
    
    def __init__(self, config: IoTDeviceConfig):
        self.config = config
        self.running = False
        self.is_active = False  # Initialize is_active
        self.data_queue = Queue()
        self.lock = Lock()
        self.batch = []
        self.sequence_number = 0
        self.last_seen = None
        
        # Initialize MQTT with proper version
        self.client = mqtt.Client(protocol=mqtt.MQTTv5)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        
        # Initialize data processor
        self.data_processor = DeviceDataProcessor(
            device_id=config.device_id,
            batch_size=config.batch_size
        )
        
        # Initialize security components
        self.zkp = SchnorrZKP()
        self.private_key, self.public_key = self.zkp.generate_keypair()
        
        # Initialize encryption
        if self.config.encryption_enabled:
            self.setup_encryption()
            
        # Setup simulation
        self.simulate_data = True
        self.simulation_interval = 1.0  # seconds
        
    def setup_encryption(self):
        """Initialize encryption components"""
        self.public_key, self.private_key = paillier.generate_paillier_keypair()
    
    def encrypt_data(self, data):
        """Encrypt data using Paillier encryption"""
        try:
            if isinstance(data, str):
                data = int.from_bytes(data.encode(), 'big')
            elif isinstance(data, bytes):
                data = int.from_bytes(data, 'big')
            
            encrypted = self.public_key.encrypt(data)
            return base64.b64encode(str(encrypted.ciphertext()).encode()).decode()
            
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data"""
        try:
            decoded = base64.b64decode(encrypted_data.encode())
            ciphertext = int(decoded.decode())
            encrypted_value = paillier.EncryptedNumber(
                self.public_key,
                ciphertext
            )
            decrypted = self.private_key.decrypt(encrypted_value)
            
            try:
                byte_length = (decrypted.bit_length() + 7) // 8
                return decrypted.to_bytes(byte_length, 'big').decode()
            except:
                return decrypted
                
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise
    
        # Initialize security components
        self.zkp = SchnorrZKP()
        self.private_key, self.public_key = self.zkp.generate_keypair()




    def generate_sensor_data(self):
        """Generate simulated sensor data"""
        data = {
            'temperature': round(20 + 5 * np.random.random(), 2),
            'humidity': round(50 + 10 * np.random.random(), 2),
            'pressure': round(1000 + 20 * np.random.random(), 2),
            'timestamp': time.time()
        }
        return data

    async def start(self):
        """Start device operation"""
        self.running = True
        try:
            self.client.connect(MQTT_BROKER, MQTT_PORT, 60, clean_start=True)
            self.client.loop_start()
            while self.running:
                if self.simulate_data:
                    data = self.generate_sensor_data()
                    if self.config.encryption_enabled:
                        data = {k: self.encrypt_data(str(v)) for k, v in data.items()}
                    await self._process_data_batch(data)
                await asyncio.sleep(self.simulation_interval)
        except Exception as e:
            logger.error(f"Device error: {str(e)}")
            self.stop()
   

    

    def stop(self):
        """Stop device operation"""
        self.running = False
        self.client.loop_stop()
        self.client.disconnect()
        
    async def _process_data_batch(self):
        """Process and publish data batch"""
        async with self.lock:
            if len(self.batch) >= self.config.batch_size:
                try:
                    batch_data = {
                        'device_id': self.config.device_id,
                        'timestamp': time.time(),
                        'sequence': self.sequence_number,
                        'data': self.batch
                    }
                    
                    # Create ZKP proof for batch
                    batch_data['proof'] = self.zkp.create_proof(str(self.batch).encode())
                    
                    message = json.dumps(batch_data)
                    self.client.publish(self.config.mqtt_topic, message)
                    self.sequence_number += 1
                    
                    await self.data_processor.process({
                        'device_id': self.config.device_id,
                        'sequence': self.sequence_number,
                        'data': self.batch
                    })
                    
                    self.batch = []
                    
                except Exception as e:
                    logger.error(f"Batch processing error: {str(e)}")
    
    def _on_connect(self, client, userdata, flags, reasonCode, properties=None):
   
       if reasonCode == 0:
           self.is_active = True
           self.client.subscribe(self.config.mqtt_topic)
           logger.info(f"Connected to {self.config.mqtt_topic}")
       else:
           logger.error(f"Connection failed with reason code {reasonCode}")

    def _on_message(self, client, userdata, message, properties=None):
    
       try:
          payload = json.loads(message.payload.decode())
          self.handle_command(payload)
       except Exception as e:
           logger.error(f"Message handling error: {str(e)}")
            
    def get_metric_data(self, metric: str) -> List[float]:
        """Get metric data for visualization"""
        return self.data_processor.get_metric_data(metric)
    async def _process_data_batch(self):
        """Process and publish data batch"""
        async with self.lock:
            if len(self.batch) >= self.config.batch_size:
                try:
                    batch_data = {
                        'device_id': self.config.device_id,
                        'timestamp': time.time(),
                        'sequence': self.sequence_number,
                        'data': self.batch
                    }
                    
                    if self.config.encryption_enabled:
                        batch_data = self._encrypt_batch(batch_data)
                    
                    # Create ZKP proof for batch
                    batch_data['proof'] = self.zkp.create_proof(str(self.batch).encode())
                    
                    message = json.dumps(batch_data)
                    self.client.publish(self.config.mqtt_topic, message)
                    self.sequence_number += 1
                    
                    await self.data_processor.process({
                        'device_id': self.config.device_id,
                        'sequence': self.sequence_number,
                        'data': self.batch
                    })
                    
                    self.batch = []
                    
                except Exception as e:
                    logger.error(f"Batch processing error: {str(e)}")
    
    def _encrypt_batch(self, batch_data: dict) -> dict:
        """Encrypt batch data using Paillier encryption"""
        try:
            encrypted_data = []
            for item in batch_data['data']:
                if isinstance(item, (int, float)):
                    encrypted_value = self.public_key.encrypt(item)
                    encrypted_data.append(str(encrypted_value.ciphertext()))
                else:
                    encrypted_value = self.public_key.encrypt(
                        int.from_bytes(str(item).encode(), 'big')
                    )
                    encrypted_data.append(str(encrypted_value.ciphertext()))
            
            batch_data['data'] = encrypted_data
            return batch_data
            
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise

    def handle_command(self, command: dict):
        """Handle incoming device commands"""
        try:
            cmd_type = command.get('type')
            if cmd_type == 'CONFIG_UPDATE':
                self._update_config(command.get('config', {}))
            elif cmd_type == 'STOP':
                self.stop()
            elif cmd_type == 'STATUS_REQUEST':
                self._send_status()
            else:
                logger.warning(f"Unknown command type: {cmd_type}")
                
        except Exception as e:
            logger.error(f"Command handling error: {str(e)}")
class IoTDeviceGUI:
    def __init__(self, root):
        """Initialize GUI with proper component creation order"""
        self.root = root
        self.root.title("IoT Device Management System")
        
        # Initialize storage
        self.devices = {}
        self.performance_data = []
        
        # Initialize all variables first
        self.init_variables()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(pady=10, expand=True, fill='both')
        
        # Create device management tab first (contains device tree)
        self.create_device_management_tab()
        
        # Create other tabs that depend on device tree
        self.create_security_tab()
        self.create_key_management_tab()
        self.create_performance_tab()
        self.create_batch_processing_tab()
        self.create_data_monitoring_tab()
        
        # Create status bar
        self.create_status_bar()
        
        # Setup core components last
        self.setup_core_components()
        
        # Start monitoring with a delay
        self.root.after(1000, self.start_monitoring)

    def init_variables(self):
        """Initialize all GUI variables"""
        self.status_var = tk.StringVar(value="Initializing...")
        self.device_id_var = tk.StringVar()
        self.device_type_var = tk.StringVar()
        self.owner_var = tk.StringVar()
        self.mqtt_topic_var = tk.StringVar()
        self.batch_size_var = tk.StringVar(value="100")
        self.message_var = tk.StringVar()
        self.enc_data_var = tk.StringVar()
        self.cpu_var = tk.StringVar(value="0%")
        self.mem_var = tk.StringVar(value="0 MB")
        self.active_devices_var = tk.StringVar(value="0")





    def update_device_list(self):
        """Update device list with proper error checking"""
        try:
            if not hasattr(self, 'device_tree') or self.device_tree is None:
                logger.error("Device tree not initialized")
                return
                
            # Clear existing items
            for item in self.device_tree.get_children():
                self.device_tree.delete(item)
            
            # Add devices to tree
            for device_id, device in self.devices.items():
                status = "Active" if device.running else "Inactive"
                trust_score = "N/A"
                last_seen = (
                    time.strftime('%H:%M:%S', time.localtime(device.last_seen))
                    if hasattr(device, 'last_seen') and device.last_seen 
                    else "Never"
                )
                
                self.device_tree.insert(
                    '',
                    'end',
                    values=(
                        device_id,
                        device.config.device_type,
                        device.config.owner_address,
                        status,
                        trust_score,
                        last_seen
                    )
                )
            
            # Update combo boxes if they exist
            device_list = list(self.devices.keys())
            
            if hasattr(self, 'key_device_combo') and self.key_device_combo is not None:
                self.key_device_combo['values'] = device_list
                
            if hasattr(self, 'batch_device_combo') and self.batch_device_combo is not None:
                self.batch_device_combo['values'] = device_list
                
            if hasattr(self, 'monitor_device_combo') and self.monitor_device_combo is not None:
                self.monitor_device_combo['values'] = device_list
                
        except Exception as e:
            logger.error(f"Device list update error: {str(e)}")
            self.status_var.set(f"Error updating device list: {str(e)}")

    def verify_zkp(self):
        """Verify ZKP with proper error handling"""
        try:
            if not hasattr(self, 'key_device_combo') or self.key_device_combo is None:
                logger.error("Key device combo not initialized")
                return
                
            device_id = self.key_device_combo.get()
            if not device_id:
                messagebox.showwarning("Selection Required", "Please select a device")
                return
            
            device = self.devices.get(device_id)
            if not device:
                messagebox.showerror("Device Not Found", 
                    f"Device {device_id} not found. Please refresh the device list.")
                return
            
            # Initialize ZKP if needed
            if not hasattr(device, 'zkp') or device.zkp is None:
                device.zkp = SchnorrZKP()
                device.private_key, device.public_key = device.zkp.generate_keypair()
            
            message = self.message_var.get()
            if not message:
                messagebox.showwarning("Input Required", "Please enter a message")
                return
            
            # Create and verify proof
            proof = device.zkp.create_proof(message.encode())
            is_valid = device.zkp.verify_proof(
                message.encode(),
                proof,
                device.zkp.y
            )
            
            if is_valid:
                messagebox.showinfo("ZKP Verification", "Proof is valid!")
            else:
                messagebox.showwarning("ZKP Verification", "Proof is invalid!")
            
        except Exception as e:
            logger.error(f"ZKP verification error: {str(e)}")
            messagebox.showerror("Verification Error", str(e))

    def create_key_management_tab(self):
        """Create key management tab with proper initialization"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Key Management")
        
        # Device selection frame
        device_frame = ttk.Frame(tab)
        device_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(device_frame, text="Device:").pack(side='left')
        self.key_device_combo = ttk.Combobox(
            device_frame,
            state='readonly',
            values=list(self.devices.keys())  # Initialize with current devices
        )
        self.key_device_combo.pack(side='left', expand=True, fill='x', padx=(5, 0))

    

    def init_variables(self):
        """Initialize all GUI variables"""
        self.status_var = tk.StringVar(value="Initializing...")
        self.device_id_var = tk.StringVar()
        self.device_type_var = tk.StringVar()
        self.owner_var = tk.StringVar()
        self.mqtt_topic_var = tk.StringVar()
        self.batch_size_var = tk.StringVar(value="100")
        self.message_var = tk.StringVar()
        self.enc_data_var = tk.StringVar()
        self.cpu_var = tk.StringVar(value="0%")
        self.mem_var = tk.StringVar(value="0 MB")
        self.active_devices_var = tk.StringVar(value="0")

    def setup_core_components(self):
    
     try:
        # Initialize MQTT with MQTTv5
        self.mqtt_client = mqtt.Client(
            client_id=f"gui_{int(time.time())}", 
            protocol=mqtt.MQTTv5,
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2
        )
        
        self.mqtt_client.connect(
            MQTT_BROKER, 
            MQTT_PORT, 
            60,
            clean_start=True
        )
        self.mqtt_client.loop_start()
        
        logger.info("Core components initialized successfully")
        self.status_var.set("System initialized successfully!")
        
     except Exception as e:
        logger.error(f"Core initialization error: {str(e)}")
        messagebox.showerror("Initialization Error", str(e))


    



        
    def _verify_components(self):
        """Verify all required components exist"""
        required_components = [
            'batch_device_combo',
            'key_device_combo',
            'monitor_device_combo',
            'device_tree'
        ]
        
        missing = []
        for component in required_components:
            if not hasattr(self, component):
                missing.append(component)
                
        if missing:
            raise AttributeError(f"Missing required components: {', '.join(missing)}")




 

    def verify_iot_data_zkp(self):
        """Verify ZKP for IoT device data"""
        try:
            device_id = self.key_device_combo.get()
            if not device_id:
                raise ValueError("Please select a device")
            
            device = self.devices.get(device_id)
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            if not device.is_active:
                raise ValueError(f"Device {device_id} is not active. Please start the device first.")
            
            # Get latest sensor data
            sensor_data = device.generate_sensor_data()
            
            # Create proof for the sensor data
            data_str = json.dumps(sensor_data)
            proof = device.zkp.create_proof(data_str.encode())
            
            # Verify the proof
            is_valid = device.zkp.verify_proof(
                data_str.encode(),
                proof,
                device.zkp.y
            )
            
            if is_valid:
                # Display encrypted data
                encrypted_data = device.encrypt_data(data_str)
                proof_info = (
                    f"ZKP Verification Successful!\n\n"
                    f"Original Data:\n{json.dumps(sensor_data, indent=2)}\n\n"
                    f"Encrypted Data:\n{encrypted_data}\n\n"
                    f"Proof Details:\n"
                    f"Commitment: {proof[0]}\n"
                    f"Challenge: {proof[1]}\n"
                    f"Response: {proof[2]}"
                )
                self.encrypted_data_text.delete('1.0', tk.END)
                self.encrypted_data_text.insert('1.0', proof_info)
                messagebox.showinfo("ZKP Verification", "IoT data proof is valid!")
            else:
                messagebox.showerror("ZKP Verification", "IoT data proof is invalid!")
            
        except Exception as e:
            logger.error(f"ZKP verification error: {str(e)}")
            messagebox.showerror("Verification Error", str(e))
    
    def refresh_encrypted_data(self):
        """Refresh encrypted IoT data display"""
        try:
            device_id = self.key_device_combo.get()
            if not device_id:
                raise ValueError("Please select a device")
            
            device = self.devices.get(device_id)
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            if not device.is_active:
                raise ValueError(f"Device {device_id} is not active. Please start the device first.")
            
            # Get and display latest encrypted data
            sensor_data = device.generate_sensor_data()
            encrypted_data = device.encrypt_data(json.dumps(sensor_data))
            
            display_text = (
                f"Latest IoT Data from {device_id}:\n\n"
                f"Original Data:\n{json.dumps(sensor_data, indent=2)}\n\n"
                f"Encrypted Data:\n{encrypted_data}"
            )
            
            self.encrypted_data_text.delete('1.0', tk.END)
            self.encrypted_data_text.insert('1.0', display_text)
            
        except Exception as e:
            logger.error(f"Data refresh error: {str(e)}")
            messagebox.showerror("Refresh Error", str(e))
    
    def update_device_status(self, device_id: str, status: str):
        """Update device status in Treeview"""
        try:
            for item in self.device_tree.get_children():
                if self.device_tree.item(item)['values'][0] == device_id:
                    device = self.devices[device_id]
                    self.device_tree.item(
                        item,
                        values=(
                            device_id,
                            device.config.device_type,
                            device.config.owner_address,
                            status
                        )
                    )
                    break
                    
            # Update device comboboxes
            self._update_device_comboboxes()
            
        except Exception as e:
            logger.error(f"Status update error: {str(e)}")
            
    def _update_device_comboboxes(self):
        """Update all device comboboxes"""
        try:
            device_list = list(self.devices.keys())
            
            if hasattr(self, 'key_device_combo'):
                self.key_device_combo['values'] = device_list
                
            if hasattr(self, 'batch_device_combo'):
                self.batch_device_combo['values'] = device_list
                
            if hasattr(self, 'monitor_device_combo'):
                self.monitor_device_combo['values'] = device_list
                
        except Exception as e:
            logger.error(f"Combobox update error: {str(e)}")
   
    def create_data_monitoring_tab(self):
        """Create data monitoring tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Data Monitoring")
        
        # Real-time data visualization
        vis_frame = ttk.LabelFrame(tab, text="Real-time Data")
        vis_frame.pack(padx=10, pady=5, fill='both', expand=True)
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(6, 4), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=vis_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
        
        # Data filtering
        filter_frame = ttk.Frame(vis_frame)
        filter_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Device:").pack(side='left')
        self.monitor_device_combo = ttk.Combobox(
            filter_frame,
            state='readonly'
        )
        self.monitor_device_combo.pack(side='left', padx=5)
        
        ttk.Label(filter_frame, text="Metric:").pack(side='left')
        self.metric_combo = ttk.Combobox(
            filter_frame,
            values=['Temperature', 'Humidity', 'Pressure', 'Custom'],
            state='readonly'
        )
        self.metric_combo.pack(side='left', padx=5)
        
        ttk.Button(
            filter_frame,
            text="Update Plot",
            command=self.update_plot
        ).pack(side='left', padx=5)
        
        # Statistics Frame
        stats_frame = ttk.LabelFrame(tab, text="Statistics")
        stats_frame.pack(padx=10, pady=5, fill='x')
        
        self.stats_text = tk.Text(stats_frame, height=5)
        self.stats_text.pack(padx=5, pady=5, fill='x')
    
    def create_batch_processing_tab(self):
        """Create batch processing tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Batch Processing")
        
        # Batch configuration
        config_frame = ttk.LabelFrame(tab, text="Batch Configuration")
        config_frame.pack(padx=10, pady=5, fill='x')
        
        # Batch size
        size_frame = ttk.Frame(config_frame)
        size_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(size_frame, text="Batch Size:").pack(side='left')
        ttk.Entry(
            size_frame,
            textvariable=self.batch_size_var
        ).pack(side='left', fill='x', expand=True)
        
        # Device selection
        batch_device_frame = ttk.Frame(config_frame)
        batch_device_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(batch_device_frame, text="Device:").pack(side='left')
        self.batch_device_combo = ttk.Combobox(
            batch_device_frame,
            state='readonly'
        )
        self.batch_device_combo.pack(side='left', fill='x', expand=True)
        
        # Control buttons
        batch_button_frame = ttk.Frame(config_frame)
        batch_button_frame.pack(pady=5)
        
        ttk.Button(
            batch_button_frame,
            text="Start Processing",
            command=self.start_batch_processing
        ).pack(side='left', padx=5)
        
        ttk.Button(
            batch_button_frame,
            text="Stop Processing",
            command=self.stop_batch_processing
        ).pack(side='left', padx=5)
        
        # Batch status
        status_frame = ttk.LabelFrame(tab, text="Processing Status")
        status_frame.pack(padx=10, pady=5, fill='both', expand=True)
        
        # Create Treeview for batch status
        columns = ("Batch ID", "Device", "Size", "Status", "Timestamp")
        self.batch_tree = ttk.Treeview(
            status_frame,
            columns=columns,
            show="headings"
        )
        
        for col in columns:
            self.batch_tree.heading(col, text=col)
            self.batch_tree.column(col, width=100)
        
        scrollbar = ttk.Scrollbar(
            status_frame,
            orient="vertical",
            command=self.batch_tree.yview
        )
        self.batch_tree.configure(yscrollcommand=scrollbar.set)
        
        self.batch_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Batch statistics
        batch_stats_frame = ttk.LabelFrame(tab, text="Batch Statistics")
        batch_stats_frame.pack(padx=10, pady=5, fill='x')
        
        self.batch_stats_text = tk.Text(batch_stats_frame, height=4)
        self.batch_stats_text.pack(padx=5, pady=5, fill='x')
    
 
    
    def create_status_bar(self):
        """Create status bar"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side='bottom', fill='x')
        
        self.status_bar = ttk.Label(
            status_frame,
            textvariable=self.status_var,
            relief='sunken'
        )
        self.status_bar.pack(fill='x', padx=5, pady=5)
    






    def create_all_tabs(self):
    
        self.create_device_management_tab()
        self.create_security_tab()
        self.create_performance_tab()
        self.create_batch_processing_tab()
        self.create_data_monitoring_tab()
        self.create_key_management_tab()  # Add this line
    def create_device_management_tab(self):
        """Create device management tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Device Management")
        # Device selection frame
        device_frame = ttk.Frame(tab)
        device_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(device_frame, text="Device:").pack(side='left')
        self.key_device_combo = ttk.Combobox(
           device_frame,
           state='readonly',
           values=[]  # Initialize empty, will be populated in update_device_list
       )
        self.key_device_combo.pack(side='left', expand=True, fill='x', padx=(5, 0))
        # Registration Frame
        reg_frame = ttk.LabelFrame(tab, text="Device Registration")
        reg_frame.pack(padx=10, pady=5, fill='x')
        # Device ID
        id_frame = ttk.Frame(reg_frame)
        id_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(id_frame, text="Device ID:").pack(side='left')
        ttk.Entry(
            id_frame,
            textvariable=self.device_id_var
        ).pack(side='left', fill='x', expand=True)
        # Device Type
        type_frame = ttk.Frame(reg_frame)
        type_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(type_frame, text="Device Type:").pack(side='left')
        device_type_combo = ttk.Combobox(
            type_frame,
            textvariable=self.device_type_var,
            values=['Sensor', 'Actuator', 'Gateway', 'Edge Device'],
            state='readonly'
        )
        device_type_combo.pack(side='left', fill='x', expand=True)
        # Owner Address
        owner_frame = ttk.Frame(reg_frame)
        owner_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(owner_frame, text="Owner Address:").pack(side='left')
        ttk.Entry(
            owner_frame,
            textvariable=self.owner_var
        ).pack(side='left', fill='x', expand=True)
        # MQTT Topic
        topic_frame = ttk.Frame(reg_frame)
        topic_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(topic_frame, text="MQTT Topic:").pack(side='left')
        ttk.Entry(
            topic_frame,
            textvariable=self.mqtt_topic_var
        ).pack(side='left', fill='x', expand=True)
        # Register Button
        ttk.Button(
            reg_frame,
            text="Register Device",
            command=self.register_device
        ).pack(pady=10)
        # Device List
        list_frame = ttk.LabelFrame(tab, text="Registered Devices")
        list_frame.pack(padx=10, pady=5, fill='both', expand=True)
        # Create Treeview
        columns = ("ID", "Type", "Owner", "Status", "Last Seen")
        self.device_tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show="headings"
        )
        # Configure columns
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=100)
        scrollbar = ttk.Scrollbar(
            list_frame,
            orient="vertical",
            command=self.device_tree.yview
        )
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        self.device_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        # Control buttons
        control_frame = ttk.Frame(tab)
        control_frame.pack(pady=5)
        ttk.Button(
            control_frame,
            text="Start Device",
            command=self.start_device
        ).pack(side='left', padx=5)
        ttk.Button(
            control_frame,
            text="Stop Device",
            command=self.stop_device
        ).pack(side='left', padx=5)
        ttk.Button(
            control_frame,
            text="Delete Device",
            command=self.delete_device
        ).pack(side='left', padx=5)


    def create_security_tab(self):
    
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Security")
    
    # Initialize security components
        self.security_module = SecurityModule()  # Initialize SecurityModule
    
    # Encryption Frame
        enc_frame = ttk.LabelFrame(tab, text="Paillier Encryption")
        enc_frame.pack(padx=10, pady=5, fill='x')
    # Encryption data input
        enc_data_frame = ttk.Frame(enc_frame)
        enc_data_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(enc_data_frame, text="Data:").pack(side='left')
        ttk.Entry(
        enc_data_frame,
        textvariable=self.enc_data_var
    ).pack(side='left', fill='x', expand=True)
    # Encryption buttons
        enc_button_frame = ttk.Frame(enc_frame)
        enc_button_frame.pack(pady=5)
        ttk.Button(
        enc_button_frame,
        text="Encrypt",
        command=self.encrypt_data
    ).pack(side='left', padx=5)
        ttk.Button(
        enc_button_frame,
        text="Decrypt",
        command=self.decrypt_data
    ).pack(side='left', padx=5)
    def create_performance_tab(self):
        """Create performance monitoring tab"""
        perf_frame = ttk.Frame(self.notebook)
        self.notebook.add(perf_frame, text="Performance")
        # Real-time metrics
        metrics_frame = ttk.LabelFrame(perf_frame, text="Real-time Metrics")
        metrics_frame.pack(padx=10, pady=5, fill='x')
        # CPU Usage
        cpu_frame = ttk.Frame(metrics_frame)
        cpu_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(cpu_frame, text="CPU Usage:").pack(side='left')
        self.cpu_var = tk.StringVar(value="0%")
        ttk.Label(cpu_frame, textvariable=self.cpu_var).pack(side='right')
        # Memory Usage
        mem_frame = ttk.Frame(metrics_frame)
        mem_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(mem_frame, text="Memory Usage:").pack(side='left')
        self.mem_var = tk.StringVar(value="0 MB")
        ttk.Label(mem_frame, textvariable=self.mem_var).pack(side='right')
        # Active Devices
        dev_frame = ttk.Frame(metrics_frame)
        dev_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(dev_frame, text="Active Devices:").pack(side='left')
        self.active_devices_var = tk.StringVar(value="0")
        ttk.Label(dev_frame, textvariable=self.active_devices_var).pack(side='right')

    def register_device(self):
        """Register new IoT device"""
        try:
            device_id = self.device_id_var.get().strip()
            device_type = self.device_type_var.get().strip()
            owner = self.owner_var.get().strip()
            mqtt_topic = self.mqtt_topic_var.get().strip()

            if not all([device_id, device_type, owner, mqtt_topic]):
                raise ValueError("All fields must be filled out")

            config = IoTDeviceConfig(device_id, device_type, owner, mqtt_topic)
            new_device = IoTDevice(config)

            self.devices[device_id] = new_device
            self.update_device_list()

            messagebox.showinfo("Success", f"Device {device_id} registered successfully")

            # Clear input fields
            self.device_id_var.set("")
            self.device_type_var.set("")
            self.owner_var.set("")
            self.mqtt_topic_var.set("")

        except Exception as e:
            logger.error(f"Device registration error: {str(e)}")
            messagebox.showerror("Registration Error", str(e))

    def start_device(self):
        """Start selected device"""
        try:
            selection = self.device_tree.selection()
            if not selection:
                messagebox.showwarning("Selection Required", "Please select a device")
                return

            device_id = str(self.device_tree.item(selection[0])['values'][0])
            device = self.devices.get(device_id)

            if not device:
                messagebox.showerror("Device Not Found", f"Device {device_id} not found")
                return

            asyncio.run_coroutine_threadsafe(device.start(), self.loop)
            self.status_var.set(f"Device {device_id} started successfully")
        except Exception as e:
            logger.error(f"Start device error: {str(e)}")
            messagebox.showerror("Start Error", str(e))

    def setup_async_loop(self):
        """Setup asyncio event loop"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        self.thread = threading.Thread(
            target=self._run_async_loop,
            daemon=True
        )
        self.thread.start()

        # Wait for loop to be running
        while not self.loop.is_running():
            time.sleep(0.1)

    def _run_async_loop(self):
        """Run asyncio event loop in separate thread"""
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()    

    def start_monitoring(self):
        """Start periodic monitoring"""
        self.update_status()
        self.monitor_performance()
        self.root.after(1000, self.start_monitoring)
    

    @measure_performance
    def stop_device(self):
        """Stop selected device"""
        try:
            selection = self.device_tree.selection()
            if not selection:
                raise ValueError("Please select a device")
            
            device_id = self.device_tree.item(selection[0])['values'][0]
            device = self.devices.get(device_id)
            
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            device.stop()
            self.status_var.set(f"Device {device_id} stopped")
            self.update_device_list()
            
        except Exception as e:
            logger.error(f"Device stop error: {str(e)}")
            messagebox.showerror("Stop Error", str(e))
    
    @measure_performance
    def delete_device(self):
        """Delete selected device"""
        try:
            selection = self.device_tree.selection()
            if not selection:
                raise ValueError("Please select a device")
            
            device_id = self.device_tree.item(selection[0])['values'][0]
            device = self.devices.get(device_id)
            
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Stop device if running
            if device.running:
                device.stop()
            
            # Delete device
            del self.devices[device_id]
            self.update_device_list()
            self.status_var.set(f"Device {device_id} deleted")
            
        except Exception as e:
            logger.error(f"Device deletion error: {str(e)}")
            messagebox.showerror("Delete Error", str(e))
    
    def generate_device_keys(self):
    
     try:
        device_id = self.key_device_combo.get()
        if not device_id:
            raise ValueError("Please select a device")
        
        device = self.devices.get(device_id)
        if not device:
            raise ValueError(f"Device {device_id} not found")
        
        # Generate keys using the device's security module
        public_key, private_key = device.security_module.generate_device_keys(device_id)
        
        key_info = (
            f"Device: {device_id}\n"
            f"Public Key: {public_key}\n"
            f"Private Key: {private_key}\n\n"
            "⚠️ IMPORTANT: Store these keys securely!"
        )
        
        messagebox.showinfo("Device Keys Generated", key_info)
        self.status_var.set(f"Keys generated for device {device_id}")
        
     except Exception as e:
        logger.error(f"Key generation error: {str(e)}")
        messagebox.showerror("Key Generation Error", str(e))
    
    def reset_device_keys(self):
        """Reset device keys"""
        try:
            device_id = self.key_device_combo.get()
            if not device_id:
                raise ValueError("Please select a device")
            
            if messagebox.askyesno(
                "Confirm Reset",
                "This will invalidate all existing keys. Continue?"
            ):
                self.generate_device_keys()
            
        except Exception as e:
            logger.error(f"Key reset error: {str(e)}")
            messagebox.showerror("Key Reset Error", str(e))
    
    def create_zkp(self):
        """Create ZKP for message"""
        try:
            device_id = self.key_device_combo.get()
            if not device_id:
                raise ValueError("Please select a device")
            
            message = self.message_var.get()
            if not message:
                raise ValueError("Please enter a message")
            
            device = self.devices.get(device_id)
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Create and verify proof
            proof = device.zkp.create_proof(message.encode())
            is_valid = device.zkp.verify_proof(
                message.encode(),
                proof,
                device.zkp.y
            )
            
            if is_valid:
                messagebox.showinfo("ZKP Verification", "Proof is valid!")
            else:
                messagebox.showerror("ZKP Verification", "Proof is invalid!")
            
            self.status_var.set("ZK proof verification completed")
            
        except Exception as e:
            logger.error(f"ZKP verification error: {str(e)}")
            messagebox.showerror("Verification Error", str(e))
        
    def encrypt_data(self):
        """Encrypt data using Paillier encryption"""
        try:
            device_id = self.key_device_combo.get()
            if not device_id:
                raise ValueError("Please select a device")
            
            data = self.enc_data_var.get()
            if not data:
                raise ValueError("Please enter data to encrypt")
            
            device = self.devices.get(device_id)
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Encrypt data
            encrypted = device.encrypt_data(data)
            
            # Show encrypted data
            encrypted_info = (
                f"Data encrypted:\n"
                f"Original: {data}\n"
                f"Encrypted: {encrypted}"
            )
            
            messagebox.showinfo("Data Encrypted", encrypted_info)
            self.status_var.set("Data encrypted successfully")
            
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            messagebox.showerror("Encryption Error", str(e))
    
    def decrypt_data(self):
        """Decrypt data using Paillier encryption"""
        try:
            device_id = self.key_device_combo.get()
            if not device_id:
                raise ValueError("Please select a device")
            
            data = self.enc_data_var.get()
            if not data:
                raise ValueError("Please enter data to decrypt")
            
            device = self.devices.get(device_id)
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Decrypt data
            decrypted = device.decrypt_data(data)
            
            # Show decrypted data
            decrypted_info = (
                f"Data decrypted:\n"
                f"Encrypted: {data}\n"
                f"Decrypted: {decrypted}"
            )
            
            messagebox.showinfo("Data Decrypted", decrypted_info)
            self.status_var.set("Data decrypted successfully")
            
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            messagebox.showerror("Decryption Error", str(e))
    
    def start_batch_processing(self):
        """Start batch processing for selected device"""
        try:
            device_id = self.batch_device_combo.get()
            if not device_id:
                raise ValueError("Please select a device")
            
            batch_size = int(self.batch_size_var.get())
            if batch_size <= 0:
                raise ValueError("Invalid batch size")
            
            device = self.devices.get(device_id)
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Update device batch size
            device.config.batch_size = batch_size
            
            # Start batch processing
            asyncio.run_coroutine_threadsafe(
                device.start(),
                self.loop
            )
            
            self.status_var.set(f"Batch processing started for device {device_id}")
            
        except Exception as e:
            logger.error(f"Batch processing error: {str(e)}")
            messagebox.showerror("Batch Processing Error", str(e))
    
    def stop_batch_processing(self):
        """Stop batch processing for selected device"""
        try:
            device_id = self.batch_device_combo.get()
            if not device_id:
                raise ValueError("Please select a device")
            
            device = self.devices.get(device_id)
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Stop device
            device.stop()
            self.status_var.set(f"Batch processing stopped for device {device_id}")
            
        except Exception as e:
            logger.error(f"Batch stop error: {str(e)}")
            messagebox.showerror("Batch Stop Error", str(e))
    
    def create_performance_tab(self):
        """Create performance monitoring tab"""
        perf_frame = ttk.Frame(self.notebook)
        self.notebook.add(perf_frame, text="Performance")
        
        # Real-time metrics
        metrics_frame = ttk.LabelFrame(perf_frame, text="Real-time Metrics")
        metrics_frame.pack(padx=10, pady=5, fill='x')
        
        # CPU Usage
        cpu_frame = ttk.Frame(metrics_frame)
        cpu_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(cpu_frame, text="CPU Usage:").pack(side='left')
        self.cpu_var = tk.StringVar(value="0%")
        ttk.Label(cpu_frame, textvariable=self.cpu_var).pack(side='right')
        
        # Memory Usage
        mem_frame = ttk.Frame(metrics_frame)
        mem_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(mem_frame, text="Memory Usage:").pack(side='left')
        self.mem_var = tk.StringVar(value="0 MB")
        ttk.Label(mem_frame, textvariable=self.mem_var).pack(side='right')
        
        # Active Devices
        dev_frame = ttk.Frame(metrics_frame)
        dev_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(dev_frame, text="Active Devices:").pack(side='left')
        self.active_devices_var = tk.StringVar(value="0")
        ttk.Label(dev_frame, textvariable=self.active_devices_var).pack(side='right')
        
        # Performance history
        history_frame = ttk.LabelFrame(perf_frame, text="Performance History")
        history_frame.pack(padx=10, pady=5, fill='both', expand=True)
        
        # Create Treeview for performance history
        columns = ("Time", "Action", "Execution Time", "CPU Time", "Memory Delta")
        self.perf_tree = ttk.Treeview(
            history_frame,
            columns=columns,
            show="headings"
        )
        
        for col in columns:
            self.perf_tree.heading(col, text=col)
            self.perf_tree.column(col, width=100)
        
        scrollbar = ttk.Scrollbar(
            history_frame,
            orient="vertical",
            command=self.perf_tree.yview
        )
        self.perf_tree.configure(yscrollcommand=scrollbar.set)
        
        self.perf_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Performance chart
        chart_frame = ttk.LabelFrame(perf_frame, text="Performance Chart")
        chart_frame.pack(padx=10, pady=5, fill='both', expand=True)
        
        self.perf_fig = Figure(figsize=(6, 4), dpi=100)
        self.perf_ax = self.perf_fig.add_subplot(111)
        self.perf_canvas = FigureCanvasTkAgg(self.perf_fig, master=chart_frame)
        self.perf_canvas.get_tk_widget().pack(fill='both', expand=True)
        
        # Control buttons
        control_frame = ttk.Frame(perf_frame)
        control_frame.pack(pady=5)
        
        ttk.Button(
            control_frame,
            text="Clear History",
            command=self.clear_performance_history
        ).pack(side='left', padx=5)
        
        ttk.Button(
            control_frame,
            text="Export Data",
            command=self.export_performance_data
        ).pack(side='left', padx=5)
    
    def create_data_monitoring_tab(self):
        """Create data monitoring tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="Data Monitoring")
        
        # Real-time data visualization
        vis_frame = ttk.LabelFrame(monitor_frame, text="Real-time Data")
        vis_frame.pack(padx=10, pady=5, fill='both', expand=True)
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(6, 4), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=vis_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
        
        # Data filtering
        filter_frame = ttk.Frame(vis_frame)
        filter_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Device:").pack(side='left')
        self.monitor_device_combo = ttk.Combobox(
            filter_frame,
            state='readonly'
        )
        self.monitor_device_combo.pack(side='left', padx=5)
        
        ttk.Label(filter_frame, text="Metric:").pack(side='left')
        self.metric_combo = ttk.Combobox(
            filter_frame,
            values=['Temperature', 'Humidity', 'Pressure', 'Custom'],
            state='readonly'
        )
        self.metric_combo.pack(side='left', padx=5)
        
        ttk.Button(
            filter_frame,
            text="Update Plot",
            command=self.update_plot
        ).pack(side='left', padx=5)
        
        # Statistics Frame
        stats_frame = ttk.LabelFrame(monitor_frame, text="Statistics")
        stats_frame.pack(padx=10, pady=5, fill='x')
        
        self.stats_text = tk.Text(stats_frame, height=5)
        self.stats_text.pack(padx=5, pady=5, fill='x')
        try:
            # Clear existing items
            for item in self.device_tree.get_children():
                self.device_tree.delete(item)
            
            # Add devices to tree
            for device_id, device in self.devices.items():
                status = "Active" if device.running else "Inactive"
                trust_score = "N/A"  # Implement trust score calculation
                last_seen = (
                    time.strftime('%H:%M:%S', time.localtime(device.last_seen))
                    if device.last_seen else "Never"
                )
                
                self.device_tree.insert(
                    '',
                    'end',
                    values=(
                        device_id,
                        device.config.device_type,
                        device.config.owner_address,
                        status,
                        trust_score,
                        last_seen
                    )
                )
            
            # Update combo boxes
            device_list = list(self.devices.keys())
            self.key_device_combo['values'] = device_list
            self.batch_device_combo['values'] = device_list
            self.monitor_device_combo['values'] = device_list
            
        except Exception as e:
            logger.error(f"Device list update error: {str(e)}")
    
    def monitor_performance(self):
        """Update performance metrics"""
        try:
            process = psutil.Process()
            
            # Update CPU usage
            cpu_percent = process.cpu_percent()
            self.cpu_var.set(f"{cpu_percent:.1f}%")
            
            # Update memory usage
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)
            self.mem_var.set(f"{memory_mb:.1f} MB")
            
            # Update active devices
            active_count = sum(1 for device in self.devices.values() if device.running)
            self.active_devices_var.set(str(active_count))
            
            # Update performance history
            if self.performance_data:
                latest = self.performance_data[-1]
                self.perf_tree.insert(
                    '',
                    0,
                    values=(
                        latest['timestamp'],
                        latest['action'],
                        f"{latest['exec_time']:.2f}",
                        f"{latest['cpu_time']:.2f}",
                        f"{latest['mem_delta']:.2f}"
                    )
                )
                
                # Keep only last 100 entries
                if len(self.perf_tree.get_children()) > 100:
                    self.perf_tree.delete(self.perf_tree.get_children()[-1])
            
            # Update performance chart
            self.update_performance_plot()
            
        except Exception as e:
            logger.error(f"Performance monitoring error: {str(e)}")
    

    

    def update_performance_plot(self):
        """Update performance monitoring plot"""
        try:
            if not self.performance_data:
                return
            
            self.perf_ax.clear()
            
            # Get last 50 data points
            data = self.performance_data[-50:]
            times = range(len(data))
            
            exec_times = [d['exec_time'] for d in data]
            cpu_times = [d['cpu_time'] for d in data]
            mem_deltas = [d['mem_delta'] for d in data]
            
            self.perf_ax.plot(times, exec_times, 'b-', label='Execution Time (ms)')
            self.perf_ax.plot(times, cpu_times, 'r-', label='CPU Time (ms)')
            self.perf_ax.plot(times, mem_deltas, 'g-', label='Memory Delta (KB)')
            
            self.perf_ax.set_xlabel('Operations')
            self.perf_ax.set_ylabel('Value')
            self.perf_ax.legend()
            self.perf_ax.grid(True)
            
            self.perf_canvas.draw()
            
        except Exception as e:
            logger.error(f"Performance plot update error: {str(e)}")
    
    def clear_performance_history(self):
        """Clear performance history"""
        try:
            self.performance_data.clear()
            
            # Clear treeview
            for item in self.perf_tree.get_children():
                self.perf_tree.delete(item)
            
            # Clear plot
            self.perf_ax.clear()
            self.perf_canvas.draw()
            
            self.status_var.set("Performance history cleared")
            
        except Exception as e:
            logger.error(f"History clear error: {str(e)}")
            messagebox.showerror("Clear Error", str(e))
    
    def export_performance_data(self):
        """Export performance data to CSV"""
        try:
            if not self.performance_data:
                messagebox.showwarning(
                    "Export Warning",
                    "No performance data available"
                )
                return
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                initialfile="performance_data.csv"
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    # Write header
                    f.write("timestamp,action,exec_time,cpu_time,mem_delta\n")
                    
                    # Write data
                    for data in self.performance_data:
                        f.write(
                            f"{data['timestamp']},"
                            f"{data['action']},"
                            f"{data['exec_time']:.2f},"
                            f"{data['cpu_time']:.2f},"
                            f"{data['mem_delta']:.2f}\n"
                        )
                
                self.status_var.set("Performance data exported successfully")
                
        except Exception as e:
            logger.error(f"Data export error: {str(e)}")
            messagebox.showerror("Export Error", str(e))

    def create_batch_processing_tab(self):
        """Create batch processing tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Batch Processing")
        
        # Batch configuration
        config_frame = ttk.LabelFrame(tab, text="Batch Configuration")
        config_frame.pack(padx=10, pady=5, fill='x')
        
        # Batch size
        size_frame = ttk.Frame(config_frame)
        size_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(size_frame, text="Batch Size:").pack(side='left')
        ttk.Entry(
            size_frame,
            textvariable=self.batch_size_var
        ).pack(side='left', fill='x', expand=True)
        
        # Device selection
        batch_device_frame = ttk.Frame(config_frame)
        batch_device_frame.pack(fill='x', padx=5, pady=2)
        ttk.Label(batch_device_frame, text="Device:").pack(side='left')
        self.batch_device_combo = ttk.Combobox(
            batch_device_frame,
            state='readonly'
        )
        self.batch_device_combo.pack(side='left', fill='x', expand=True)
        
        # Control buttons
        batch_button_frame = ttk.Frame(config_frame)
        batch_button_frame.pack(pady=5)
        
        ttk.Button(
            batch_button_frame,
            text="Start Processing",
            command=self.start_batch_processing
        ).pack(side='left', padx=5)
        
        ttk.Button(
            batch_button_frame,
            text="Stop Processing",
            command=self.stop_batch_processing
        ).pack(side='left', padx=5)
        
        # Batch status
        status_frame = ttk.LabelFrame(tab, text="Processing Status")
        status_frame.pack(padx=10, pady=5, fill='both', expand=True)
        
        # Create Treeview for batch status
        columns = ("Batch ID", "Device", "Size", "Status", "Timestamp")
        self.batch_tree = ttk.Treeview(
            status_frame,
            columns=columns,
            show="headings"
        )
        
        for col in columns:
            self.batch_tree.heading(col, text=col)
            self.batch_tree.column(col, width=100)
        
        # Add scrollbar to batch tree
        batch_scrollbar = ttk.Scrollbar(
            status_frame,
            orient="vertical",
            command=self.batch_tree.yview
        )
        self.batch_tree.configure(yscrollcommand=batch_scrollbar.set)
        
        self.batch_tree.pack(side='left', fill='both', expand=True)
        batch_scrollbar.pack(side='right', fill='y')
        
        # Batch statistics
        batch_stats_frame = ttk.LabelFrame(tab, text="Batch Statistics")
        batch_stats_frame.pack(padx=10, pady=5, fill='x')
        
        self.batch_stats_text = tk.Text(batch_stats_frame, height=4)
        self.batch_stats_text.pack(padx=5, pady=5, fill='x')
        try:
            device_id = self.key_device_combo.get()
            if not device_id:
                raise ValueError("Please select a device")
            
            message = self.message_var.get()
            if not message:
                raise ValueError("Please enter a message")
            
            device = self.devices.get(device_id)
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Create and verify proof
            proof = device.zkp.create_proof(message.encode())
            is_valid = device.zkp.verify_proof(
                message.encode(),
                proof,
                device.zkp.y
            )
            
            if is_valid:
                messagebox.showinfo("ZKP Verification", "Proof is valid!")
            else:
                messagebox.showerror("ZKP Verification", "Proof is invalid!")
            
            self.status_var.set("ZK proof verification completed")
            
        except Exception as e:
            logger.error(f"ZKP verification error: {str(e)}")
            messagebox.showerror("Verification Error", str(e))
            
    def update_plot(self):
        """Update data visualization plot"""
        try:
            device_id = self.monitor_device_combo.get()
            metric = self.metric_combo.get()
            
            if not device_id or not metric:
                self.ax.clear()
                self.ax.set_title("Select device and metric")
                self.canvas.draw()
                return
            
            device = self.devices.get(device_id)
            if not device:
                self.ax.clear()
                self.ax.set_title("Device not found")
                self.canvas.draw()
                return
            
            # Get device data
            data = []
            if metric == 'Temperature':
                data = [d.get('temperature', 0) for d in device.data_processor.metric_data.get('temperature', [])]
            elif metric == 'Humidity':
                data = [d.get('humidity', 0) for d in device.data_processor.metric_data.get('humidity', [])]
            elif metric == 'Pressure':
                data = [d.get('pressure', 0) for d in device.data_processor.metric_data.get('pressure', [])]
            
            if not data:
                self.ax.clear()
                self.ax.set_title("No data available")
                self.canvas.draw()
                return
            
            # Plot data
            self.ax.clear()
            timestamps = range(len(data))
            self.ax.plot(timestamps, data, 'b-', label=metric)
            self.ax.set_xlabel('Time')
            self.ax.set_ylabel(metric)
            self.ax.set_title(f'{metric} vs Time for {device_id}')
            self.ax.grid(True)
            self.ax.legend()
            
            self.canvas.draw()
            
            # Update statistics
            self.update_statistics(data, metric)
            
        except Exception as e:
            logger.error(f"Plot update error: {str(e)}")
            self.ax.clear()
            self.ax.set_title("Error updating plot")
            self.canvas.draw()

    def update_statistics(self, data, metric):
        """Update statistics display"""
        try:
            stats = (
                f"Statistics for {metric}:\n"
                f"Mean: {np.mean(data):.2f}\n"
                f"Std Dev: {np.std(data):.2f}\n"
                f"Min: {np.min(data):.2f}\n"
                f"Max: {np.max(data):.2f}"
            )
            
            self.stats_text.delete('1.0', tk.END)
            self.stats_text.insert('1.0', stats)
            
        except Exception as e:
            logger.error(f"Statistics update error: {str(e)}")
            self.stats_text.delete('1.0', tk.END)
            self.stats_text.insert('1.0', "Error calculating statistics")
        try:
            # Clear existing items
            for item in self.device_tree.get_children():
                self.device_tree.delete(item)
            
            # Add devices to tree
            for device_id, device in self.devices.items():
                status = "Active" if device.running else "Inactive"
                trust_score = "N/A"  # Implement trust score calculation
                last_seen = (
                    time.strftime('%H:%M:%S', time.localtime(device.last_seen))
                    if device.last_seen else "Never"
                )
                
                self.device_tree.insert(
                    '',
                    'end',
                    values=(
                        device_id,
                        device.config.device_type,
                        device.config.owner_address,
                        status,
                        trust_score,
                        last_seen
                    )
                )
            
            # Update combo boxes
            device_list = list(self.devices.keys())
            self.key_device_combo['values'] = device_list
            self.batch_device_combo['values'] = device_list
            self.monitor_device_combo['values'] = device_list
            
        except Exception as e:
            logger.error(f"Device list update error: {str(e)}")
            messagebox.showerror("Update Error", str(e))
    
    def _monitor_performance(self):
        """Update performance metrics"""
        try:
            process = psutil.Process()
            
            # Update CPU usage
            cpu_percent = process.cpu_percent()
            self.cpu_var.set(f"{cpu_percent:.1f}%")
            
            # Update memory usage
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)
            self.mem_var.set(f"{memory_mb:.1f} MB")
            
            # Update performance chart
            self.update_performance_plot()
            
            # Schedule next update
            self.root.after(1000, self._monitor_performance)
            
        except Exception as e:
            logger.error(f"Performance monitoring error: {str(e)}")
    
    def start_monitoring(self):
        """Start system monitoring"""
        self.update_device_list()
        self._monitor_performance()

def main():
    """Main application entry point"""
    try:
        root = tk.Tk()
        root.title("IoT Device Management System")
        root.geometry("1200x800")
        app = IoTDeviceGUI(root)  # Create GUI instance
        root.mainloop()           # Start main loop
    except Exception as e:
        logger.error(f"Application startup error: {str(e)}")
        messagebox.showerror(
            "Startup Error",
            f"Application failed to start: {str(e)}"
        )

if __name__ == "__main__":
    main()                        # Call main without .get().get()
    def create_zkp(self):
        """Create ZKP for message"""
        try:
            device_id = self.key_device_combo.get()
            if not device_id:
                raise ValueError("Please select a device")
            
            message = self.message_var.get()
            if not message:
                raise ValueError("Please enter a message")
            
            device = self.devices.get(device_id)
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Create proof
            proof = device.zkp.create_proof(message.encode())
            
            # Show proof information
            proof_info = (
                f"ZK Proof created:\n"
                f"Commitment: {proof[0]}\n"
                f"Challenge: {proof[1]}\n"
                f"Response: {proof[2]}"
            )
            
            messagebox.showinfo("ZK Proof Created", proof_info)
            self.status_var.set("ZK proof created successfully")
            
        except Exception as e:
            logger.error(f"ZKP creation error: {str(e)}")
            messagebox.showerror("ZKP Error", str(e))
    
    def verify_zkp(self):
        """Verify ZKP"""
        try:
            device_id = self.key_device_combo.get()
            if not device_id:
                raise ValueError("Please select a device")
            
            message = self.message_var.get()
            if not message:
                raise ValueError("Please enter a message")
            
            device = self.devices.get(device_id)
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Create and verify proof
            proof = device.zkp.create_proof(message.encode())
            is_valid = device.zkp.verify_proof(
                message.encode(),
                proof,
                device.zkp.y
            )
            
            if is_valid:
                messagebox.showinfo("ZKP Verification", "Proof is valid!")
            else:
                messagebox.showerror("ZKP Verification", "Proof is invalid!")
            
            self.status_var.set("ZK proof verification completed")
            
        except Exception as e:
            logger.error(f"ZKP verification error: {str(e)}")
            messagebox.showerror("Verification Error", str(e))   