FROM python:3.9-slim

# VULNERABILIDAD CONTROLADA: Imagen base con CVE conocidos
# Python 3.9 tiene varias vulnerabilidades conocidas (usar 3.11+ en producción)

WORKDIR /app

# Instalar dependencias
RUN pip install --no-cache-dir paho-mqtt==1.6.1

# VULNERABILIDAD: paho-mqtt 1.6.1 tiene CVE-2021-34431 (severity: low)
# Descripción: Improper certificate validation
# Referencia: https://nvd.nist.gov/vuln/detail/CVE-2021-34431

# Copiar scripts de sensores
COPY temperature_sensor.py .
COPY soil_moisture_sensor.py .

# Usuario no root
RUN useradd -m sensoruser
USER sensoruser

# El CMD se especifica en docker-compose.yml