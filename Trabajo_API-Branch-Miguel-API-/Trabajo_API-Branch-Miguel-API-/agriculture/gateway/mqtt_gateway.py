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
from collections import defaultdict

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
        self.detected_vulnerabilities = set()              # Para evitar duplicados en vulnerabilidades reportadas      
        self.sensor_telemetry = defaultdict(dict)

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
        
    def on_connect(self, client, userdata, flags, rc):
        """un callback para cuando se conecta con el broker de MQTT
        Gestiona el resultado de la conexión con el broker"""
        #Para conexión exitosa
        if rc == 0:
            logger.info(f"Connected to MQTT Broker: {MQTT_BROKER}:{MQTT_PORT}")
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

    def process_sensor_data(self, topic: str, payload: Dict[str, Any]):
        """Procesa los datos del sensor y envía"""

        sensor_id = payload.get("sensor_id")
        asset_id = payload.get("asset_id")

        if not sensor_id or not asset_id:
            logger.warning("Missing sensor_id or asset_id in payload")
            return

        logger.info(f"Processing data from sensor {sensor_id} (Asset ID: {asset_id})")
        
        # 1. Almacenar telemetría
        if "telemetry" in payload:
            self.sensor_telemetry[sensor_id] = {
                "timestamp": payload.get("timestamp"),
                "data": payload["telemetry"]
            }
            logger.info(f"Telemetry: {payload['telemetry']}")

        if "vulnerabilities" in payload:
            vulnerabilities = payload["vulnerabilities"]
            logger.info(f" Found{len(vulnerabilities)} vulnerabilities")

            for vuln in vulnerabilities:
                self.report_vulnerability(vuln, asset_id)

        self.update_asset_if_needed(asset_id, payload)

    def report_vulnerability(self, vuln_data: Dict, asset_id: int):
        """Reportar vulnerabilidad a la API"""
        cve_id = vuln_data.get("cve_id")
        # Evitar duplicados
        cache_key = f"{cve_id}_{asset_id}"
        if cache_key in self.detected_vulnerabilities:
            logger.debug(f"Vulnerability {cve_id} already reported for asset {asset_id}")
            return
        headers = {"Authorization":f"Bearer {self.api_token}"}

        try:
            vuln_id = self.ensure_vulnerability_exists(vuln_data)

            if not vuln_id:
                logger.error(f"Failed to get vulnerability ID for {cve_id}")
                return
        
            response = requests.post(
                f"{API_URL}/api/vulnerabilities/assets{asset_id}/vulnerabilities/{vuln_id}",
                headers=headers,
                timeout=10
            )

            if response.status_code in [200,201]:
                self.detected_vulnerabilities.add(cache_key)
                logger.warning(f"NEW VULNERABILITY LINKED: {cve_id} --> ASSET {asset_id} (SEVERITY: {vuln_data.get('severity')})")
            elif response.status_code == 400 and "Already Linked" in response.text:
                self.detected_vulnerabilities.add(cache_key)
                logger.debug(f"Vulnerability {cve_id} already linked to asset {asset_id}")
            else:
                logger.error(f"Failed to link vulnerability: {response.status_code} - {response.text}")

        except Exception as e:
            logger.error(f"Error reporting vulnerability: {e}")

    def ensure_vulnerability_exists(self, vuln_data: Dict) -> int | None:
        cve_id = vuln_data.get("cve_id")
        headers = {"Authorization": f"Bearer {self.api_token}"}
        
        try:
            # Buscar si ya existe
            response = requests.get(
                f"{API_URL}/api/vulnerabilities/",
                params={"search": cve_id},
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                vulns = response.json()
                for v in vulns:
                    if v["cve_id"] == cve_id:
                        return v["id"]
            
            # No existe, crear nueva
            logger.info(f" Creating new vulnerability: {cve_id}")
            
            # Mapear severity al formato esperado
            severity_map = {
                "low": "low",
                "medium": "medium",
                "high": "high",
                "critical": "critical"
            }
            
            vuln_create_data = {
                "cve_id": cve_id,
                "title": vuln_data.get("description", f"Vulnerability {cve_id}")[:200],
                "description": vuln_data.get("description", "No description provided"),
                "severity": severity_map.get(vuln_data.get("severity", "medium").lower(), "medium"),
                "published_date": datetime.now().isoformat(),
                "references": vuln_data.get("references", "")
            }
            
            response = requests.post(
                f"{API_URL}/api/vulnerabilities/",
                json=vuln_create_data,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 201:
                created = response.json()
                logger.info(f" Created vulnerability: {cve_id} (ID: {created['id']})")
                return created["id"]
            else:
                logger.error(f" Failed to create vulnerability: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f" Error ensuring vulnerability exists: {e}")
            return None
        
    def update_asset_if_needed(self, asset_id: int, payload: Dict):
        """Actualizar nivel de riesgo del activo según vulnerabilidades"""
        
        if "vulnerabilities" not in payload:
            return
        
        # Determinar el nivel de riesgo más alto
        severities = [v.get("severity", "low").lower() for v in payload["vulnerabilities"]]
        
        risk_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_severity = max(severities, key=lambda s: risk_priority.get(s, 0))
        
        # Solo actualizar si es crítico o alto
        if max_severity in ["critical", "high"]:
            headers = {"Authorization": f"Bearer {self.api_token}"}
            
            try:
                response = requests.put(
                    f"{API_URL}/assets/{asset_id}",
                    json={"risk_level": max_severity},
                    headers=headers,
                    timeout=10
                )
                
                if response.status_code == 200:
                    logger.warning(f" Asset {asset_id} risk level updated to {max_severity.upper()}")
                else:
                    logger.debug(f"Could not update asset risk: {response.status_code}")
                    
            except Exception as e:
                logger.error(f" Error updating asset risk: {e}")
    
    def run(self):
        """Ejecutar gateway"""
        try:
            # Autenticar con la API
            if not self.authenticate_api():
                logger.error(" Failed to authenticate with API, exiting")
                return
            
            # Conectar al broker MQTT
            logger.info(f" Connecting to {MQTT_BROKER}:{MQTT_PORT}...")
            self.client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
            
            logger.info(" MQTT Gateway started successfully")
            logger.info(" Listening for sensor data and detecting vulnerabilities...")
            
            # Loop forever
            self.client.loop_forever()
            
        except KeyboardInterrupt:
            logger.info(" MQTT Gateway stopped by user")
        except Exception as e:
            logger.error(f" Gateway error: {e}", exc_info=True)
        finally:
            self.client.disconnect()

if __name__ == "__main__":
    gateway = MQTTGateway()
    gateway.run()