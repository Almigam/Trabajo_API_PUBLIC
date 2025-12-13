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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
SENSOR_ID = os.getenv("SENSOR_ID", "soil_cap_001")
ASSET_ID = int(os.getenv("ASSET_ID", "11"))
LOCATION = os.getenv("LOCATION", "field_section_b")
PUBLISH_INTERVAL = int(os.getenv("PUBLISH_INTERVAL", "30"))

class SoilMoistureSensor:
    """Simulador de sensor de humedad de suelo"""
    
    def __init__(self):
        self.client = mqtt.Client(client_id=SENSOR_ID)
        self.client.on_connect = self.on_connect
        
        # Valores base (suelo agrícola típico)
        self.base_vwc = 30.0  # % volumétrico
        self.irrigation_active = False
        self.last_irrigation = None
        
        # VULNERABILIDAD: Buffer overflow simulado (CWE-120)
        # Este buffer pequeño puede desbordarse con datos grandes
        self.data_buffer = bytearray(64)  # Solo 64 bytes
        
    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info(f"Connected to MQTT Broker")
            # Suscribirse a comandos de riego
            client.subscribe(f"agriculture/actuators/irrigation/{SENSOR_ID}/command")
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
            "sensor_id": SENSOR_ID,
            "asset_id": ASSET_ID,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "sensor_type": "soil_moisture",
            "readings": {
                "volumetric_water_content": {
                    "value": vwc,
                    "unit": "percent"
                },
                "soil_status": soil_status,
                "temperature": {
                    "value": round(random.uniform(15, 25), 2),
                    "unit": "celsius"
                }
            },
            "location": {
                "zone": LOCATION,
                "depth": {
                    "value": 30,
                    "unit": "cm"
                }
            },
            "metadata": {
                "battery_level": round(random.uniform(70, 100), 2),
                "signal_strength": random.randint(-85, -60)
            }
        }
        
        # VULNERABILIDAD: Intentar almacenar payload grande en buffer pequeño
        # Esto simula un buffer overflow (solo para demostración)
        try:
            payload_bytes = json.dumps(payload).encode('utf-8')
            if len(payload_bytes) > len(self.data_buffer):
                logger.warning(f" VULNERABILITY: Buffer overflow detected! "
                            f"Payload size {len(payload_bytes)} > buffer size {len(self.data_buffer)}")
        except Exception as e:
            logger.error(f"Buffer overflow simulation: {e}")
        
        return payload
    
    def run(self):
        try:
            self.client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
            self.client.loop_start()
            
            logger.info(f"Soil Moisture Sensor {SENSOR_ID} started")
            
            while True:
                payload = self.generate_payload()
                topic = f"agriculture/sensors/soil_moisture/{SENSOR_ID}"
                
                self.client.publish(topic, json.dumps(payload), qos=1)
                
                logger.info(f"Published: VWC={payload['readings']['volumetric_water_content']['value']}% "
                        f"({payload['readings']['soil_status']})")
                
                time.sleep(PUBLISH_INTERVAL)
                
        except KeyboardInterrupt:
            logger.info("Sensor stopped")
        finally:
            self.client.loop_stop()
            self.client.disconnect()

if __name__ == "__main__":
    sensor = SoilMoistureSensor()
    sensor.run()