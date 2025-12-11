"""
MQTT Gateway - Puente entre sensores MQTT y Asset Inventory API

Funcionalidad:
1. Suscribirse a todos los topics de sensores.ve    
2. Parsear mensajes JSON
3. Registrar/actualizar activos en la API
4. Almacenar lecturas de sensores
"""

import paho.mqtt.client as mqtt
import json
import requests
import os
import logging 
from datetime import datetime
from typing import Dict, Any

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuración
MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
API_URL = os.getenv("API_URL", "http://asset-api:8000")
API_USERNAME = os.getenv("API_USERNAME", "admin")
API_PASSWORD = os.getenv("API_PASSWORD", "Admin123!@#")

class MQTTGateway:
    """Gateway entre MQTT y API REST"""
    
    def __init__(self):
        self.client = mqtt.Client(client_id="mqtt_gateway")
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        
        self.api_token = None
        self.sensor_readings = {}
    
    def authenticate_api(self) -> bool:
        """Auntenticar con la API y obtener JWT"""
        try:
            response = requests.post(
                f"{API_URL}/auth/login",
                data={
                    "username": API_USERNAME,
                    "password": API_PASSWORD
                }, 
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                self.api_token = data["access_token"]
                logger.info("Authenticated with Asset API")
                return True
            else:
                logger.error(f"Authentication failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"API authentication error: {e}")
            return False
        
    def on_connect(self, client, rc):
        """un callback para cuando se conecta con el broker de MQTT"""
        if rc == 0:
            logger.info(f"Connected to MQTT Broker: {MQTT_BROKER}")
            #El cliente tiene que subscribirse a todos los topics de los sensores.
            client.subscribe("agriculture/sensors/#")
            logger.info("Subscribed to: agriculture/sensors/#")
        else:
            logger.error(f"Connection failed with code {rc}")

    def on_message(self, msg):
        """Callback para cuando se recibe mensaje MQTT"""
        try:
            #Parsear el payload del JSON
            payload = json.loads(msg.payload.decode('utf-8'))
            logger.info(f"Received from {msg.topic}")
            logger.debug(f"Payload: {json.dumps(payload, indent=2)}")
            #Procesar JSON según tipo sensor
            self.process_sensor_data(msg.topic, payload)

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON {e}")
        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)
    
    def process_sensor_data(self, topic: str, payload: Dict[str, Any]):
        """Procesa los datos del sensor y envía"""

        #QUEDA: TERMINAR ESTA FUNCIÓN Y AÑADIR CHECKEOS Y CREAR LOS ASSETS PARA CADA SENSOR