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
        pass