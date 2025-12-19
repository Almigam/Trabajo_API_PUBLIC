API de Inventario de Activos IT - Proyecto de Programación Segura
Este proyecto implementa una API REST segura para la gestión de activos de TI, desarrollada como parte de la asignatura de Programación Segura. El sistema incluye autenticación robusta, control de acceso basado en roles (RBAC), gestión de vulnerabilidades y un módulo de simulación IoT para Agricultura 4.0.

 Tabla de Contenidos

Características Principales
Arquitectura del Sistema
Tecnologías Utilizadas
Requisitos Previos
Instalación y Configuración
Módulo IoT Agriculture 4.0
Seguridad Implementada
Estructura del Proyecto
Documentación Adicional
Recursos de Aprendizaje


 Características Principales
 Seguridad Robusta

Autenticación JWT con tokens de acceso y refresco
Hashing Argon2id para contraseñas (migración desde bcrypt)
Control de acceso basado en roles (RBAC): Usuario y Administrador
Rate limiting para prevenir ataques de fuerza bruta
Cabeceras de seguridad HTTP (CSP, X-Frame-Options, HSTS, etc.)
Validación estricta de entradas con Pydantic
Logging seguro sin exposición de datos sensibles

 Gestión de Activos IT

CRUD completo de activos (servidores, estaciones de trabajo, dispositivos de red, etc.)
Filtrado y paginación avanzados
Estadísticas en tiempo real
Niveles de riesgo dinámicos (Bajo, Medio, Alto, Crítico)
Gestión de ciclo de vida (Activo, Inactivo, Mantenimiento, Fuera de Servicio)

 Gestión de Vulnerabilidades

Registro y seguimiento de vulnerabilidades (CVE)
Vinculación automática con activos
Escalado automático de nivel de riesgo
Puntuación CVSS y referencias

 Módulo IoT Agriculture 4.0

Simulación de sensores IoT (temperatura, humedad, humedad del suelo)
Broker MQTT (Mosquitto)
Gateway que detecta vulnerabilidades en tiempo real
Integración con la API de activos
Vulnerabilidades controladas para propósitos educativos

 Frontend Moderno

Interfaz de usuario responsive
Dashboard interactivo con estadísticas
Sistema de autenticación visual
Diseño moderno con gradientes y animaciones

```
 Arquitectura del Sistema
┌─────────────────┐
│   Frontend      │ (NGINX + HTML/CSS/JS)
│   Dashboard     │
└────────┬────────┘
         │ HTTP/REST
         ↓
┌─────────────────┐
│   FastAPI       │ (Python 3.12)
│   Backend       │ - Autenticación JWT
│                 │ - RBAC
│                 │ - Rate Limiting
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ↓         ↓
┌─────────┐ ┌──────────────┐
│SQLModel │ │ MQTT Gateway │
│PostgreSQL│ │  (IoT)       │
└─────────┘ └──────┬───────┘
                   │
                   ↓
            ┌──────────────┐
            │  Mosquitto   │
            │  MQTT Broker │
            └──────┬───────┘
                   │
        ┌──────────┴──────────┐
        ↓                     ↓
    [Sensores IoT]    [Sensores IoT]
    Temperatura       Humedad Suelo
```

 Tecnologías Utilizadas
Backend

FastAPI 0.115.0 - Framework web moderno y rápido
SQLModel 0.0.21 - ORM basado en Pydantic y SQLAlchemy
PostgreSQL 15 - Base de datos relacional
PyJWT - Manejo de JWT
Argon2-CFFI - Hashing de contraseñas
Uvicorn - Servidor ASGI

Frontend

NGINX Alpine - Servidor web
HTML5/CSS3/JavaScript - Interfaz moderna
Fetch API - Comunicación con el backend

IoT

Eclipse Mosquitto 2.0.15 - Broker MQTT
Paho-MQTT 1.6.1 - Cliente MQTT para Python
Docker Compose - Orquestación de contenedores

Seguridad y Testing

Bandit - Análisis SAST para Python
Semgrep - Análisis de código estático
Trivy - Escaneo de vulnerabilidades en contenedores
Pip-audit - Auditoría de dependencias
Pytest - Framework de testing


 Requisitos Previos

Docker 20.10+ y Docker Compose 2.0+
Python 3.12+ (para desarrollo local)
Git 2.30+



 Instalación y Configuración

Levantar los servicios ejecutando el archivo setup.sh
sudo ./setup.sh

Acceder a la aplicación
API: http://localhost:8000
Frontend: http://localhost (si está configurado)


 Módulo IoT Agriculture 4.0
El proyecto incluye una simulación de infraestructura IoT para agricultura inteligente con vulnerabilidades controladas para propósitos educativos.
Componentes

Broker MQTT (Mosquitto 2.0.15)

Puerto 1883 (MQTT)
Puerto 9001 (WebSocket)
CVE-2023-0809: Memory leak (severidad media)


Sensores Simulados

DHT22 (Temperatura y humedad)
Credenciales hardcodeadas (CWE-798)
Firmware vulnerable

Capacitivo (Humedad del suelo)
Buffer overflow simulado (CWE-120)

MQTT Gateway
Detecta vulnerabilidades automáticamente
Reporta a la API de activos
Actualiza niveles de riesgo


```

### Vulnerabilidades Detectadas

El gateway detecta automáticamente:
-  CVE-2024-TEMP-001: Credenciales hardcodeadas en firmware DHT22
-  CVE-2024-SOIL-001: Riesgo de buffer overflow en sensor capacitivo
-  CVE-2023-MQTT-003: Comunicación MQTT sin cifrar
-  CVE-2024-BROKER-001: Broker sin autenticación
-  CVE-2023-0809: Memory leak en Mosquitto 2.0.15


##  Seguridad Implementada

###  Controles por Capa

#### 1. Autenticación y Autorización
-  JWT con firma HMAC-SHA256
-  Access tokens (15 min) y refresh tokens (7 días)
-  RBAC con roles `user` y `admin`
-  Endpoint `/auth/refresh` seguro
-  Verificación de ownership en recursos

#### 2. Cifrado y Hashing
-  **Argon2id** para contraseñas (migración desde bcrypt)
-  Parámetros robustos: time_cost=2, memory_cost=64MB
-  Sal aleatoria por usuario
-  Rehashing automático si cambian parámetros

#### 3. Validación de Entradas
-  Pydantic para todos los modelos
-  Validación de tipos, longitud y formato
-  Regex para username y contraseñas
-  Validación de direcciones IP (IPv4/IPv6)
-  Sanitización de búsquedas SQL con `ilike`

#### 4. Rate Limiting
-  Límite global: 1000 req/hora por IP
-  Login: 5 req/minuto
-  Registro: 3 req/minuto
-  Refresh: 10 req/minuto
-  Respuestas 429 con `Retry-After`



6. Gestión de Errores

 Mensajes genéricos al cliente
 Stack traces solo en logs
 Logging estructurado con contexto
 No exposición de detalles internos

7. Logging Seguro

 Rotación automática (10 MB, 5 backups)
 No se loguean contraseñas ni tokens
 Timestamp, nivel y módulo en cada log
 Separación de logs de aplicación y acceso

```
##  Estructura del Proyecto
```
Trabajo_API/
├── app/
│   ├── core/
│   │   ├── database.py          # Configuración de base de datos
│   │   ├── security.py          # JWT, hashing, RBAC
│   │   ├── rate_limit.py        # Configuración de rate limiting
│   │   └── logging_config.py    # Configuración de logging
│   ├── models/
│   │   ├── asset.py             # Modelos de BD (User, Asset, Vulnerability)
│   │   └── schemas.py           # Esquemas Pydantic
│   ├── routers/
│   │   ├── auth/
│   │   │   └── auth.py          # Endpoints de autenticación
│   │   ├── users/
│   │   │   └── users.py         # Endpoints de usuarios
│   │   ├── assets/
│   │   │   └── assets.py        # Endpoints de activos
│   │   ├── vulnerabilities/
│   │   │   └── vulnerabilities.py # Endpoints de vulnerabilidades
│   │   └── messages/
│   │       └── messages.py      # Endpoints de mensajes
│   └── main.py                  # Aplicación principal
├── frontend/
│   ├── css/                    
│   │   |── css.py               # Estilos CSS
│   │   └── vulnerabilities.py   # Vulnerabilidades de CSS
│   ├── js/                      
│   │   |── js.py                # JavaScript
│   │   └── vulnerabilities.py   # Vulnerabilidades de JavaScript
│   ├── certs/                   # Certificados
│   ├── index.html               # Página de login
│   ├── register.html            # Página de registro
│   ├── dashboard.html           # Dashboard principal
│   ├── nginx.conf               # Configuración NGINX
│   └── Dockerfile               # Dockerfile del frontend
├── agriculture-iot/
│   ├── mosquitto/               # Configuración del broker MQTT
│   ├── sensors/                 # Simuladores de sensores
│   ├── nginx_certs/             # Certificados de nginx
│   ├── gateway/                 # Gateway MQTT → API
│   ├── docs/                    # Documentación de CVEs
│   └── docker-compose.yml       # Orquestación IoT
├── docs/
│   ├── architecture.md          # Arquitectura del sistema
│   ├── threat_model.md          # Modelo de amenazas
│   └── informe_técnico.md       # Informe final
├── scripts/
│   ├── scan_bandit.sh           # Script de Bandit
│   ├── scan_semgrep.sh          # Script de Semgrep
│   ├── scan_pip_audit.sh        # Script de pip-audit
│   ├── scan_trivy_fs.sh         # Script de Trivy FS
│   ├── scan_trivy_image.sh      # Script de Trivy Image
│   └── scan_zap_baseline.sh     # Script de ZAP
├── tests/
│   ├── conftest.py              # Configuración de tests
│   ├── test_auth.py             # Tests de autenticación
│   └── test_assets.py           # Tests de activos
├── logs/                        # Logs de la aplicación
├── requirements.txt             # Dependencias Python
├── .env.example                 # Ejemplo de variables de entorno
├── .dockerignore                # Archivo para definir lo que no se copia al contenedor
├── Dockerfile                   # Archivo para inicio de Docker
├── docker-compose.yml           # Archivo para levantar múltiples contenedores de Docker
├── reset_system.sh              # Script para reinicio del sistema
├── audit_security.sh            # Script para auditar la seguridad
├── setup.sh                     # Script para inicio
└── README.md                    # Este archivo

```

##  Documentación Adicional

- **[Documentación de la API (Swagger)]** https://localhost/api/docs
- **[Informe Técnico]** `docs/informe_técnico.md`


##  Recursos de Aprendizaje

- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP API Security](https://owasp.org/API-Security/)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)







