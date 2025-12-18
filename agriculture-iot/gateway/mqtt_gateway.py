"""
MQTT Gateway - Versión Inteligente (Sin duplicados y con tipos correctos)
"""
import paho.mqtt.client as mqtt
import json
import requests
import os
import time
import logging 
from datetime import datetime
from typing import Dict, Any

# Configuración de Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuración de Variables de Entorno
MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
API_URL = os.getenv("API_URL", "http://localhost:8002")
API_USERNAME = os.getenv("API_USERNAME", "admin")
API_PASSWORD = os.getenv("API_PASSWORD", "admin123")

class MQTTGateway:
    def __init__(self):
        self.client = mqtt.Client(client_id="mqtt_gateway")
        self.client.on_connect = self.on_connect
        self.client.on_message = self.on_message
        self.api_token = None
        
        # MEMORIA DEL ROBOT: Diccionario para guardar { "Nombre Sensor": ID_Base_Datos }
        self.asset_memory = {} 

    def authenticate_api(self) -> bool:
        """Autenticar y obtener Token"""
        logger.info(f"🔑 Autenticando en API como {API_USERNAME}...")
        try:
            response = requests.post(
                f"{API_URL}/auth/login",
                data={"username": API_USERNAME, "password": API_PASSWORD}, 
                timeout=10
            )
            if response.status_code == 200:
                self.api_token = response.json()["access_token"]
                logger.info("✅ Token obtenido correctamente.")
                self.load_existing_assets() # <--- AL LOGUEARSE, CARGAMOS LA MEMORIA
                return True
            else:
                logger.error(f"❌ Error Login: {response.text}")
                return False
        except Exception as e:
            logger.error(f"❌ Error conexión Login: {e}")
            return False

    def load_existing_assets(self):
        """Descarga la lista de activos actuales para no duplicarlos"""
        try:
            headers = {"Authorization": f"Bearer {self.api_token}"}
            response = requests.get(f"{API_URL}/assets/", headers=headers)
            if response.status_code == 200:
                assets = response.json()
                # Guardamos en memoria: { "Sensor IoT: temp_001": 5, ... }
                for asset in assets:
                    self.asset_memory[asset["name"]] = asset["id"]
                logger.info(f"🧠 Memoria cargada: {len(self.asset_memory)} activos reconocidos.")
        except Exception as e:
            logger.error(f"⚠️ No pude cargar la memoria inicial: {e}")

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info("✅ Conectado a MQTT. Suscribiendo...")
            client.subscribe("agriculture/sensors/#")
        else:
            logger.error(f"❌ Error MQTT: {rc}")

    def on_message(self, client, userdata, msg):
        try:
            payload = json.loads(msg.payload.decode('utf-8'))
            self.process_sensor_data(payload) # Simplificado
        except Exception as e:
            logger.error(f"Error procesando mensaje: {e}")

    def process_sensor_data(self, payload: Dict[str, Any]):
        if not self.api_token:
            if not self.authenticate_api(): return

        sensor_id = payload.get("sensor_id", "unknown")
        val = payload.get("value", 0)
        unit = payload.get("unit", "")
        
        asset_name = f"Sensor IoT: {sensor_id}"
        
        # AHORA SÍ: Usamos 'sensor' porque ya está en schemas.py
        asset_data = {
            "name": asset_name,
            "asset_type": "sensor",  
            "description": f"Lectura en vivo: {val} {unit}",
            "ip_address": "192.168.1.50", # Obligatorio que sea formato IP válido
            "hostname": sensor_id,
            # No enviamos 'status' ni 'risk_level' porque son opcionales en tu schema
        }

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

        try:
            # Intentamos crear
            resp = requests.post(f"{API_URL}/assets/", json=asset_data, headers=headers)
            
            if resp.status_code in [200, 201]:
                logger.info(f"✨ Nuevo Sensor Creado: {asset_name}")
                self.asset_memory[asset_name] = resp.json().get("id")
            elif resp.status_code == 409: 
                # Si ya existe, aquí podrías hacer el PUT, pero por ahora ignóralo
                logger.info(f"Sensor ya existe: {asset_name}")
            else:
                logger.warning(f"⚠️ Falló creación: {resp.status_code} - {resp.text}")

        except Exception as e:
            logger.error(f"Error HTTP: {e}")

    def run(self):
        while True:
            try:
                self.client.connect(MQTT_BROKER, MQTT_PORT, 60)
                break
            except:
                time.sleep(5)
        
        self.authenticate_api()
        self.client.loop_forever()

if __name__ == "__main__":
    MQTTGateway().run()