"""
MQTT Gateway - Puente entre sensores MQTT y Asset Inventory API

Funcionalidad:
1. Suscribirse a todos los topics de sensores.ve    
2. Parsear mensajes JSON
3. Registrar/actualizar activos en la API
4. Almacenar lecturas de sensores
"""

import paho.mqtt.client as mqtt # Cliente MQTT (paho) para conectarse al broker y manejar mensajes
import json                     # generar/parsear json
import requests                 # Request HTTP a API
import os                       # leer env
import logging                  # logs, errores
from datetime import datetime   # marcas de tiempo
from typing import Dict, Any, List

logging.basicConfig(
    # muestra información relevante y advertencias
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuración
MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")     # Host de MQTT
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))         # Puerto MQTT
API_URL = os.getenv("API_URL", "http://asset-api:8000") # URL API
API_USERNAME = os.getenv("API_USERNAME", "admin")       # Usuario autenticación (SE CONFIGURA EN EL ENTORNO)
API_PASSWORD = os.getenv("API_PASSWORD", "Admin123!@#") # password autenticación (SE CONFIGURA EN EL ENTORNO)

class MQTTGateway:
    """Gateway entre MQTT y API REST, conexión MQTT y comunicación con API"""
    
    def __init__(self):
        
        self.client = mqtt.Client(client_id="mqtt_gateway") # Cliente MQTT con su id
        self.client.on_connect = self.on_connect 
        self.client.on_message = self.on_message                
        self.api_token = None                               # Token JWT guarda tras ok auth
        self.sensor_readings = {}                           # Caché/estructura para lecturas de sensores
        self.detected_vulnerabilities = set()       
    
    def authenticate_api(self) -> bool:
        """Auntenticar con la API y obtener JWT,
        login en API si consigue guarda token JWT"""
        try:
            response = requests.post(
                f"{API_URL}/auth/login",        # Endpoint de login API 
                # Datos que se mandan en la auntenticación
                data={
                    "username": API_USERNAME,
                    "password": API_PASSWORD
                }, 
                timeout=10                      # Tiempo max de espera para respuesta 
            )
            # API OK -> parsea en JSON, extrae JWT y almacena.
            if response.status_code == 200:
                data = response.json()
                self.api_token = data["access_token"]
                logger.info("Authenticated with Asset API")
                return True
            
            # API NO OK -> log con el fallo
            else:
                logger.error(f"Authentication failed: {response.status_code}")
                return False
            # PARA ERRORES INESPERADOS
        except Exception as e:
            logger.error(f"API authentication error: {e}")
            return False
        
    def on_connect(self, client, rc):
        """un callback para cuando se conecta con el broker de MQTT
        Gestiona el resultado de la conexión con el broker"""
        #Para conexión exitosa
        if rc == 0:
            logger.info(f"Connected to MQTT Broker: {MQTT_BROKER}")
            #El cliente tiene que subscribirse a todos los topics de los sensores.
            client.subscribe("agriculture/sensors/#")
            #Confirmación suscripción
            logger.info("Subscribed to: agriculture/sensors/#")
        
        # Conexión NO exitosa -> Log error
        else:
            logger.error(f"Connection failed with code {rc}")

    def on_message(self, client, userdata, msg):
        """Callback para cuando se recibe mensaje MQTT, 
        Cualquier mensaje desde topic suscrito"""
        try:
            #Parsear el payload del JSON, decodificar, informar al topic
            payload = json.loads(msg.payload.decode('utf-8'))
            logger.info(f"Received from {msg.topic}")
            logger.debug(f"Payload: {json.dumps(payload, indent=2)}")
            #Procesar JSON según tipo sensor
            self.process_sensor_data(msg.topic, payload)

        #Si payload JSON no válido
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON {e}")
        #Error genérico con traceback
        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)
    
        def detect_vulnerabilities(self, sensor_type: str, payload: Dict) -> List[Dict]:
        """Detecta vulnerabilidades basándose en los datos del sensor"""
        vulnerabilities = []
        
        # 1. Credenciales hardcodeadas
        if sensor_type == "temperature_humidity":
            firmware_version = payload.get("metadata", {}).get("firmware_version")
            if firmware_version in ["1.2.3", "1.2.4"]:
                vulnerabilities.append({
                    "cve_id": "CVE-2024-TEMP-001",
                    "severity": "high",
                    "description": "Hardcoded admin credentials detected in sensor firmware",
                    "affected_component": f"DHT22 Firmware {firmware_version}",
                    "asset_id": payload.get("asset_id")
                })
        
        # 2. Buffer overflow
        if sensor_type == "soil_moisture":
            payload_size = len(json.dumps(payload).encode('utf-8'))
            if payload_size > 64:
                vulnerabilities.append({
                    "cve_id": "CVE-2024-SOIL-001",
                    "severity": "critical",
                    "description": f"Buffer overflow risk detected (payload: {payload_size} bytes > 64 byte buffer)",
                    "affected_component": "Capacitive Sensor Buffer",
                    "asset_id": payload.get("asset_id")
                })
        
        # 3. Comunicación sin cifrar
        vulnerabilities.append({
            "cve_id": "CVE-2023-MQTT-003",
            "severity": "medium",
            "description": "MQTT communication is unencrypted (port 1883)",
            "affected_component": "MQTT Protocol",
            "asset_id": payload.get("asset_id")
        })
        
        # 4. Broker sin autenticación
        vulnerabilities.append({
            "cve_id": "CVE-2024-BROKER-001",
            "severity": "high",
            "description": "MQTT broker allows anonymous connections",
            "affected_component": "Mosquitto Configuration",
            "asset_id": None
        })
        
        # 5. CVE conocido del broker
        vulnerabilities.append({
            "cve_id": "CVE-2023-0809",
            "severity": "medium",
            "description": "Memory leak vulnerability in Mosquitto 2.0.15",
            "affected_component": "Eclipse Mosquitto 2.0.15",
            "asset_id": None
        })
        
        # 6. Batería baja
        battery = payload.get("metadata", {}).get("battery_level", 100)
        if battery < 20:
            vulnerabilities.append({
                "cve_id": f"CVE-CUSTOM-BAT-{payload.get('sensor_id')}",
                "severity": "low",
                "description": f"Critical battery level: {battery}% - Risk of data loss",
                "affected_component": payload.get("sensor_id", "Unknown"),
                "asset_id": payload.get("asset_id")
            })
        
        return vulnerabilities
    
    def report_vulnerability_to_api(self, vuln_data: Dict):
        """Enviar vulnerabilidad detectada a la API"""
        
        # Evitar duplicación de activos
        vuln_key = vuln_data["cve_id"]
        # Comprobar si se reportó y si es así lanzar error
        if vuln_key in self.detected_vulnerabilities:
            logger.debug(f"Vulnerability {vuln_key} already reported, skipping")
            return
        
        # Cabecera de autenticacón con token JWT
        headers = {"Authorization": f"Bearer {self.api_token}"}
        
        # 
        try:
            response = requests.post(
                f"{API_URL}/api/vulnerabilities/",
                json=vuln_data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 201:
                self.detected_vulnerabilities.add(vuln_key)
                logger.warning(f" NEW VULNERABILITY REPORTED: {vuln_data['cve_id']} ({vuln_data['severity']})")
            elif response.status_code == 400 and "already exists" in response.text:
                self.detected_vulnerabilities.add(vuln_key)
                logger.debug(f"Vulnerability {vuln_key} already exists in database")
            else:
                logger.error(f"Failed to report vulnerability: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"Error reporting vulnerability: {e}")
    
    def update_asset_risk_level(self, asset_id: int, severity: str):
        """Actualizar nivel de riesgo del activo según vulnerabilidades"""
        
        risk_mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low"
        }
        
        risk_level = risk_mapping.get(severity, "low")
        
        headers = {"Authorization": f"Bearer {self.api_token}"}
        
        try:
            response = requests.put(
                f"{API_URL}/assets/{asset_id}",
                json={"risk_level": risk_level},
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f" Asset {asset_id} risk level updated to {risk_level}")
            else:
                logger.warning(f"Failed to update asset risk: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error updating asset risk: {e}")
    
    def process_sensor_data(self, topic: str, payload: Dict[str, Any]):
        """Procesa los datos del sensor y envía"""
        sensor_type = payload.get("sensor_type")
        sensor_id = payload.get("sensor_id")
        asset_id = payload.get("asset_id")

        logger.info(f"Processing {sensor_type} data from {sensor_id}")
        
        # 1. Almacenar telemetría
        readings = payload.get("readings", {})
        logger.info(f"Telemetry: {json.dumps(readings, indent=2)}")
        
        # 2. Detectar vulnerabilidades
        vulnerabilities = self.detect_vulnerabilities(sensor_type, payload)
        
        # 3. Reportar vulnerabilidades a la API
        for vuln in vulnerabilities:
            self.report_vulnerability_to_api(vuln)
        
        # 4. Actualizar nivel de riesgo del activo
        critical_vulns = [v for v in vulnerabilities if v["severity"] == "critical"]
        if critical_vulns and asset_id:
            self.update_asset_risk_level(asset_id, "critical")
        
        logger.info(f" Processed sensor data - {len(vulnerabilities)} vulnerabilities detected")

        def run(self):
        """Ejecutar gateway"""
        try:
            if not self.authenticate_api():
                logger.error("Failed to authenticate with API, exiting")
                return
            
            logger.info(f"Connecting to {MQTT_BROKER}:{MQTT_PORT}...")
            self.client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
            
            logger.info(" MQTT Gateway started successfully")
            logger.info("Listening for sensor data and detecting vulnerabilities...")
            self.client.loop_forever()
            
        except KeyboardInterrupt:
            logger.info("Gateway stopped by user")
        except Exception as e:
            logger.error(f"Gateway error: {e}", exc_info=True)
        finally:
            self.client.disconnect()

if __name__ == "__main__":
    gateway = MQTTGateway()
    gateway.run()