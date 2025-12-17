"""
Simulador de Sensor de Humedad del Suelo Capacitivo
Mide humedad volumétrica del suelo (VWC)
"""
import paho.mqtt.client as mqtt
import json
import time
import random
from datetime import datetime
import os
import logging
from typing import List, Dict

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
SENSOR_ID = os.getenv("SENSOR_ID", "soil_cap_001")
ASSET_ID = int(os.getenv("ASSET_ID", "11"))
LOCATION = os.getenv("LOCATION", "field_section_b")
PUBLISH_INTERVAL = int(os.getenv("PUBLISH_INTERVAL", "30"))

class SoilMoistureSensor:
    """Simulador de sensor de humedad de suelo + detección de vulnerabilidades"""
    
    def __init__(self):
        self.client = mqtt.Client(client_id=SENSOR_ID)
        self.client.on_connect = self.on_connect
        
        # Valores base (suelo agrícola típico)
        self.base_vwc = 30.0  # % volumétrico
        self.irrigation_active = False
        # Estado del sensor
        self.firmware_version = "2.0.1"
        
        # VULNERABILIDAD: Buffer overflow simulado (CWE-120)
        # Este buffer pequeño puede desbordarse con datos grandes
        self.data_buffer = bytearray(64)  # Solo 64 bytes
        
    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info(f"Connected to MQTT Broker")
        else:
            logger.error(f"Connection failed")
    
    def generate_soil_moisture(self) -> float:
        """Generar humedad del suelo con lógica de riego"""
        
        # Si hay riego activo, incrementar humedad
        if self.irrigation_active:
            self.base_vwc = min(50.0, self.base_vwc + random.uniform(0.5, 1.5))
        else:
            # Evapotranspiración (pérdida de agua)
            self.base_vwc = max(15.0, self.base_vwc - random.uniform(0.1, 0.3))
        
        # Ruido del sensor
        noise = random.gauss(0, 1.0)
        
        return round(self.base_vwc + noise, 2)
    
    def detect_vulnerabilities(self, payload_size: int) -> List[dict]:
        """Detectar vulnerabilidades de sensor y entorno"""
        vulnerabilities = []
        # CVE-2024-SOIL-001: Buffer overflow
        if payload_size > 64:
            vulnerabilities.append({
                "cve_id": "CVE-2024-SOIL-001",
                "severity": "critical",
                "description": f"Buffer overflow risk: payload {payload_size} bytes > 64 byte buffer",
                "affected_component": f"Capacitive Sensor {SENSOR_ID}",
                "status": "open",
                "references": "https://cwe.mitre.org/data/definitions/120.html"
            })
        
        # CVE-2021-34431: paho-mqtt certificate validation
        vulnerabilities.append({
            "cve_id": "CVE-2021-34431",
            "severity": "low",
            "description": "Improper certificate validation in paho-mqtt 1.6.1",
            "affected_component": "paho-mqtt library",
            "status": "open",
            "references": "https://nvd.nist.gov/vuln/detail/CVE-2021-34431"
        })
        
        # Mismo CVE del broker
        vulnerabilities.append({
            "cve_id": "CVE-2023-0809",
            "severity": "medium",
            "description": "Memory leak vulnerability in Mosquitto 2.0.15",
            "affected_component": "Eclipse Mosquitto 2.0.15",
            "status": "open",
            "references": "https://nvd.nist.gov/vuln/detail/CVE-2023-0809"
        })
        
        return vulnerabilities
    
    def generate_payload(self) -> dict:
        vwc = self.generate_soil_moisture()
        
        # Determinar estado del suelo
        if vwc < 20:
            soil_status = "dry"
        elif vwc < 35:
            soil_status = "optimal"
        else:
            soil_status = "saturated"
        
        payload = {
            "asset_id": ASSET_ID,
            "sensor_id": SENSOR_ID,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "sensor_type": "soil_moisture",
            "location": {
                "zone": LOCATION,
                "depth_cm": 30
            },
            "telemetry": {
                "volumetric_water_content": vwc,
                "soil_status": soil_status,
                "temperature": round(random.uniform(15, 25), 2),
                "battery": round(random.uniform(70, 100), 2),
                "signal_strength": random.randint(-85, -60)
            },
            "vulnerabilities": [],
            "metadata": {
                "firmware_version": self.firmware_version
            }
        }
        # Detectar buffer overflow
        payload_bytes = json.dumps(payload).encode('utf-8')
        payload_size = len(payload_bytes)
        
        if payload_size > len(self.data_buffer):
            logger.warning(f" VULNERABILITY: Buffer overflow detected! "
                        f"Payload {payload_size} > buffer {len(self.data_buffer)}")
        payload["vulnerabilities"] = self.detect_vulnerabilities(payload_size)
        return payload
    
    def run(self):
        try:
            logger.info(f"Soil Moisture Sensor {SENSOR_ID} starting...")
            logger.info(f"Connecting to {MQTT_BROKER}:{MQTT_PORT}...")

            self.client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
            self.client.loop_start()
            
            logger.info(f" Sensor started successfully")
            logger.info(f" Publishing to: agriculture/sensors/soil_moisture/{SENSOR_ID}")
            logger.info(f" Interval: {PUBLISH_INTERVAL}s")

            while True:
                payload = self.generate_payload()
                topic = f"agriculture/sensors/soil_moisture/{SENSOR_ID}"
                
                self.client.publish(topic, json.dumps(payload), qos=1)
                
                logger.info(f"Published: VWC={payload['telemetry']['volumetric_water_content']}% "
                        f"({payload['telemetry']['soil_status']}), CVEs={len(payload['vulnerabilities'])}")
                
                time.sleep(PUBLISH_INTERVAL)
                
        except KeyboardInterrupt:
            logger.info("Sensor stopped")
        finally:
            self.client.loop_stop()
            self.client.disconnect()

if __name__ == "__main__":
    sensor = SoilMoistureSensor()
    sensor.run()