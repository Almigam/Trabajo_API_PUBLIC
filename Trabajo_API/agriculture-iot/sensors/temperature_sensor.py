"""
Simulador de Sensor de Temperatura DHT22
Simula datos de temperatura y humedad para invernadero
"""
import json
import time
import random
from datetime import datetime
import os
import logging
import paho.mqtt.client as mqtt

# VULNERABILIDAD CONTROLADA: Logging de credenciales (CWE-532)
# Se loguean datos sensibles para demostración
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuración
MQTT_BROKER = os.getenv("MQTT_BROKER", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
SENSOR_ID = os.getenv("SENSOR_ID", "temp_dht22_001")
ASSET_ID = int(os.getenv("ASSET_ID", "10"))
LOCATION = os.getenv("LOCATION", "greenhouse_a")
PUBLISH_INTERVAL = int(os.getenv("PUBLISH_INTERVAL", "10"))  # segundos

class TemperatureSensor:
    """Simulador de sensor DHT22"""
    
    def __init__(self):
        self.client = mqtt.Client(client_id=SENSOR_ID)
        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect
        
        # Valores base (simulación realista para Sevilla en noviembre)
        self.base_temp = 18.0  # °C
        self.base_humidity = 65.0  # %
        
        # Variación diurna
        self.temp_amplitude = 5.0  # ±5°C
        self.humidity_amplitude = 15.0  # ±15%
        
        # Estado del sensor
        self.battery_level = 100
        self.firmware_version = "1.2.3"
        
        # VULNERABILIDAD CONTROLADA: Credenciales hardcodeadas (CWE-798)
        # En un escenario real, esto permitiría acceso no autorizado
        self.admin_user = "admin"
        self.admin_pass = "admin123"  # Contraseña débil
        
        logger.warning(f" SECURITY: Hardcoded credentials detected: {self.admin_user}:{self.admin_pass}")
    
    def on_connect(self, client, userdata, flags, rc):
        """Callback cuando se conecta al broker"""
        if rc == 0:
            logger.info(f" Connected to MQTT Broker: {MQTT_BROKER}:{MQTT_PORT}")
        else:
            logger.error(f" Connection failed with code {rc}")
    
    def on_disconnect(self, client, userdata, rc):
        """Callback cuando se desconecta"""
        logger.warning(f" Disconnected from broker (code: {rc})")
    
    def generate_temperature(self) -> float:
        """Generar temperatura realista con variación diurna"""
        # Hora del día (0-24)
        hour = datetime.now().hour
        
        # Variación diurna (sinusoidal)
        # Pico a las 14:00, mínimo a las 6:00
        time_factor = (hour - 6) / 24.0 * 2 * 3.14159
        diurnal_variation = self.temp_amplitude * (0.5 + 0.5 * (1 + (time_factor)))
        
        # Ruido aleatorio
        noise = random.gauss(0, 0.5)
        
        temp = self.base_temp + diurnal_variation + noise
        
        # Clamp entre rangos realistas
        return round(max(10.0, min(35.0, temp)), 2)
    
    def generate_humidity(self) -> float:
        """Generar humedad relativa (inversa a temperatura)"""
        temp = self.generate_temperature()
        
        # Humedad inversamente proporcional a temperatura
        humidity = self.base_humidity - (temp - self.base_temp) * 2
        
        # Ruido
        noise = random.gauss(0, 2)
        humidity += noise
        
        # Clamp entre 30-95%
        return round(max(30.0, min(95.0, humidity)), 2)
    
    def generate_payload(self) -> dict:
        """Generar payload JSON del sensor"""
        
        # Simular descarga de batería
        self.battery_level = max(0, self.battery_level - random.uniform(0, 0.01))
        
        payload = {
            "sensor_id": SENSOR_ID,
            "asset_id": ASSET_ID,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "sensor_type": "temperature_humidity",
            "readings": {
                "temperature": {
                    "value": self.generate_temperature(),
                    "unit": "celsius"
                },
                "humidity": {
                    "value": self.generate_humidity(),
                    "unit": "percent"
                }
            },
            "location": {
                "zone": LOCATION,
                "coordinates": {
                    "lat": 37.389092,
                    "lon": -5.984459
                }
            },
            "metadata": {
                "battery_level": round(self.battery_level, 2),
                "signal_strength": random.randint(-80, -50),  # dBm
                "firmware_version": self.firmware_version
            }
        }
        
        return payload
    
    def run(self):
        """Ejecutar bucle principal del sensor"""
        try:
            # Conectar al broker
            logger.info(f"Connecting to {MQTT_BROKER}:{MQTT_PORT}...")
            self.client.connect(MQTT_BROKER, MQTT_PORT, keepalive=60)
            
            # Iniciar loop en background
            self.client.loop_start()
            
            logger.info(f"Temperature Sensor {SENSOR_ID} started")
            logger.info(f"Publishing to: agriculture/sensors/temperature/{SENSOR_ID}")
            
            while True:
                # Generar y publicar datos
                payload = self.generate_payload()
                topic = f"agriculture/sensors/temperature/{SENSOR_ID}"
                
                result = self.client.publish(
                    topic,
                    json.dumps(payload),
                    qos=1  # At least once delivery
                )
                
                if result.rc == mqtt.MQTT_ERR_SUCCESS:
                    logger.info(f"Published: Temp={payload['readings']['temperature']['value']}°C, "
                            f"Humidity={payload['readings']['humidity']['value']}%")
                else:
                    logger.error(f"Publish failed with code {result.rc}")
                
                # Esperar intervalo
                time.sleep(PUBLISH_INTERVAL)
                
        except KeyboardInterrupt:
            logger.info("Sensor stopped by user")
        except Exception as e:
            logger.error(f"Error: {e}", exc_info=True)
        finally:
            self.client.loop_stop()
            self.client.disconnect()

if __name__ == "__main__":
    sensor = TemperatureSensor()
    sensor.run()