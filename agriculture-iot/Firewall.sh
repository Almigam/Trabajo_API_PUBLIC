#!/bin/bash
# ============================================================
# Reglas de Firewall para Arquitectura IoT Segura
# Implementa Zero Trust entre zonas de red
# ============================================================

set -e

echo "🔥 Configurando reglas de firewall para IoT seguro..."

# ============================================================
# LIMPIAR REGLAS EXISTENTES
# ============================================================
echo "🧹 Limpiando reglas existentes..."

# Crear cadenas personalizadas si no existen
iptables -N DOCKER-ISOLATION-STAGE-1 2>/dev/null || true
iptables -N DOCKER-ISOLATION-STAGE-2 2>/dev/null || true
iptables -F DOCKER-ISOLATION-STAGE-1
iptables -F DOCKER-ISOLATION-STAGE-2

# ============================================================
# DEFINIR REDES (actualizar según tu configuración)
# ============================================================
APP_NET="172.20.0.0/24"          # Zona 1: Aplicación
DMZ_NET="172.21.0.0/24"          # Zona 2: DMZ
SENSORS_CRIT="172.22.0.0/24"     # Zona 3: Sensores Críticos
SENSORS_STD="172.23.0.0/24"      # Zona 4: Sensores Estándar

# IPs específicas
API_IP="172.20.0.10"
GATEWAY_IP="172.21.0.30"
MOSQUITTO_IP_DMZ="172.21.0.20"
MOSQUITTO_IP_CRIT="172.22.0.20"
MOSQUITTO_IP_STD="172.23.0.20"

echo "📋 Configuración de redes:"
echo "  ZONA 1 (App):     $APP_NET"
echo "  ZONA 2 (DMZ):     $DMZ_NET"
echo "  ZONA 3 (Crit):    $SENSORS_CRIT"
echo "  ZONA 4 (Std):     $SENSORS_STD"

# ============================================================
# REGLA 1: BLOQUEAR TODO TRÁFICO ENTRE ZONAS DE SENSORES
# ============================================================
echo "🚫 Regla 1: Bloqueando tráfico entre zonas de sensores..."

# Sensores Críticos → Sensores Estándar (DENY)
iptables -A DOCKER-ISOLATION-STAGE-2 \
    -s $SENSORS_CRIT -d $SENSORS_STD \
    -j DROP \
    -m comment --comment "DENY: Sensores críticos → estándar"

# Sensores Estándar → Sensores Críticos (DENY)
iptables -A DOCKER-ISOLATION-STAGE-2 \
    -s $SENSORS_STD -d $SENSORS_CRIT \
    -j DROP \
    -m comment --comment "DENY: Sensores estándar → críticos"

echo "  ✅ Sensores aislados entre sí"

# ============================================================
# REGLA 2: SENSORES SOLO PUEDEN HABLAR CON MOSQUITTO
# ============================================================
echo "🎯 Regla 2: Limitando sensores a MQTT..."

# Sensores Críticos → Solo Mosquitto en su zona (puerto 1883)
iptables -A DOCKER-ISOLATION-STAGE-2 \
    -s $SENSORS_CRIT \
    -d $MOSQUITTO_IP_CRIT -p tcp --dport 1883 \
    -j ACCEPT \
    -m comment --comment "ALLOW: Sensores crit → Mosquitto (MQTT)"

# Bloquear sensores críticos a cualquier otro destino
iptables -A DOCKER-ISOLATION-STAGE-2 \
    -s $SENSORS_CRIT \
    ! -d $MOSQUITTO_IP_CRIT \
    -j DROP \
    -m comment --comment "DENY: Sensores crit → otros destinos"

# Sensores Estándar → Solo Mosquitto en su zona (puerto 1883)
iptables -A DOCKER-ISOLATION-STAGE-2 \
    -s $SENSORS_STD \
    -d $MOSQUITTO_IP_STD -p tcp --dport 1883 \
    -j ACCEPT \
    -m comment --comment "ALLOW: Sensores std → Mosquitto (MQTT)"

# Bloquear sensores estándar a cualquier otro destino
iptables -A DOCKER-ISOLATION-STAGE-2 \
    -s $SENSORS_STD \
    ! -d $MOSQUITTO_IP_STD \
    -j DROP \
    -m comment --comment "DENY: Sensores std → otros destinos"

echo "  ✅ Sensores limitados a MQTT únicamente"

# ============================================================
# REGLA 3: BLOQUEAR SENSORES → API (directo)
# ============================================================
echo "🔒 Regla 3: Bloqueando acceso directo de sensores a API..."

# Sensores Críticos → API (DENY)
iptables -A DOCKER-ISOLATION-STAGE-2 \
    -s $SENSORS_CRIT -d $API_IP \
    -j DROP \
    -m comment --comment "DENY: Sensores crit → API (bypass)"

# Sensores Estándar → API (DENY)
iptables -A DOCKER-ISOLATION-STAGE-2 \
    -s $SENSORS_STD -d $API_IP \
    -j DROP \
    -m comment --comment "DENY: Sensores std → API (bypass)"

echo "  ✅ Sensores no pueden bypasear Gateway"

# ============================================================
# REGLA 4: GATEWAY → API (único camino autorizado)
# ============================================================
echo "✅ Regla 4: Permitiendo Gateway → API..."

# Gateway → API (puerto 8000) - ÚNICO PATH AUTORIZADO
iptables -A DOCKER-ISOLATION-STAGE-2 \
    -s $GATEWAY_IP -d $API_IP -p tcp --dport 8000 \
    -j ACCEPT \
    -m comment --comment "ALLOW: Gateway → API (único path)"

echo "  ✅ Gateway como choke point configurado"

# ============================================================
# REGLA 5: BLOQUEAR MOSQUITTO → API
# ============================================================
echo "🚫 Regla 5: Bloqueando Mosquitto → API..."

iptables -A DOCKER-ISOLATION-STAGE-2 \
    -s $MOSQUITTO_IP_DMZ -d $API_IP \
    -j DROP \
    -m comment --comment "DENY: Mosquitto → API"

echo "  ✅ Broker aislado de la aplicación"

# ============================================================
# REGLA 6: PERMITIR TRÁFICO LEGÍTIMO EN DMZ
# ============================================================
echo "🔓 Regla 6: Configurando DMZ..."

# Gateway → Mosquitto (para suscripción)
iptables -A DOCKER-ISOLATION-STAGE-2 \
    -s $GATEWAY_IP -d $MOSQUITTO_IP_DMZ -p tcp --dport 1883 \
    -j ACCEPT \
    -m comment --comment "ALLOW: Gateway → Mosquitto (subscribe)"

echo "  ✅ Comunicación DMZ configurada"

# ============================================================
# REGLA 7: LOGGING DE TRÁFICO BLOQUEADO (Debugging)
# ============================================================
echo "📊 Regla 7: Configurando logging..."

# Log de paquetes bloqueados para auditoría
iptables -A DOCKER-ISOLATION-STAGE-2 \
    -j LOG --log-prefix "IOT-FIREWALL-BLOCK: " --log-level 4 \
    -m limit --limit 5/min \
    -m comment --comment "LOG: Tráfico bloqueado"

echo "  ✅ Logging habilitado (5 logs/min)"

# ============================================================
# APLICAR CADENAS AL FLUJO DOCKER
# ============================================================
echo "🔗 Aplicando reglas al flujo de Docker..."

# Redirigir tráfico de Docker a nuestras cadenas personalizadas
iptables -I FORWARD 1 -j DOCKER-ISOLATION-STAGE-1
iptables -I DOCKER-ISOLATION-STAGE-1 -j DOCKER-ISOLATION-STAGE-2

# ============================================================
# REGLAS DE RATE LIMITING (Prevenir DDoS)
# ============================================================
echo "⏱️  Configurando rate limiting..."

# Limitar conexiones MQTT por sensor (máx 60 por minuto)
iptables -A DOCKER-ISOLATION-STAGE-2 \
    -p tcp --dport 1883 \
    -m connlimit --connlimit-above 10 --connlimit-mask 32 \
    -j DROP \
    -m comment --comment "RATE-LIMIT: Max 10 conexiones MQTT/sensor"

# Limitar SYN flood
iptables -A DOCKER-ISOLATION-STAGE-2 \
    -p tcp --syn \
    -m limit --limit 10/s --limit-burst 20 \
    -j ACCEPT \
    -m comment --comment "RATE-LIMIT: Anti SYN flood"

iptables -A DOCKER-ISOLATION-STAGE-2 \
    -p tcp --syn \
    -j DROP \
    -m comment --comment "RATE-LIMIT: Drop SYN flood"

echo "  ✅ Rate limiting configurado"

# ============================================================
# PERSISTIR REGLAS (Opcional)
# ============================================================
echo "💾 Guardando reglas..."

# Guardar reglas (Ubuntu/Debian)
if command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
    echo "  ⚠️  No se pudo guardar en /etc/iptables/rules.v4"
fi

# ============================================================
# VERIFICACIÓN
# ============================================================
echo ""
echo "✅ CONFIGURACIÓN COMPLETADA"
echo ""
echo "📋 Reglas activas:"
iptables -L DOCKER-ISOLATION-STAGE-2 -n --line-numbers | head -20

echo ""
echo "🧪 PRUEBAS RECOMENDADAS:"
echo ""
echo "1. Verificar aislamiento entre sensores:"
echo "   docker exec temp-sensor-001 ping -c 1 172.23.0.103"
echo "   Resultado esperado: ❌ TIMEOUT"
echo ""
echo "2. Verificar acceso sensor → Mosquitto:"
echo "   docker exec temp-sensor-001 nc -zv 172.22.0.20 1883"
echo "   Resultado esperado: ✅ CONNECTED"
echo ""
echo "3. Verificar bloqueo sensor → API:"
echo "   docker exec temp-sensor-001 curl http://172.20.0.10:8000/health"
echo "   Resultado esperado: ❌ TIMEOUT"
echo ""
echo "4. Ver logs de tráfico bloqueado:"
echo "   tail -f /var/log/syslog | grep IOT-FIREWALL-BLOCK"
echo ""
echo "⚠️  IMPORTANTE:"
echo "- Estas reglas se pierden al reiniciar el host"
echo "- Para persistir: instalar iptables-persistent"
echo "- sudo apt-get install iptables-persistent"
echo ""

# ============================================================
# FUNCIONES DE AYUDA
# ============================================================

# Función para listar todas las reglas
list_rules() {
    echo "📋 Todas las reglas de firewall IoT:"
    iptables -L DOCKER-ISOLATION-STAGE-2 -n -v --line-numbers
}

# Función para eliminar todas las reglas
cleanup_rules() {
    echo "🧹 Eliminando todas las reglas IoT..."
    iptables -F DOCKER-ISOLATION-STAGE-1
    iptables -F DOCKER-ISOLATION-STAGE-2
    echo "✅ Reglas eliminadas"
}

# Exportar funciones para uso posterior
export -f list_rules
export -f cleanup_rules

echo "💡 Comandos disponibles:"
echo "   list_rules      - Listar todas las reglas"
echo "   cleanup_rules   - Eliminar todas las reglas"
