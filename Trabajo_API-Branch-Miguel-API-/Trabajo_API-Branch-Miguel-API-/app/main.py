from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging
import os
from app.middleware.security_headers import SecurityHeadersMiddleware
from fastapi.middleware.cors import CORSMiddleware
from app.core.logging_config import setup_logging
from app.core.database import create_db_and_tables
from app.routers.users import users
from app.routers.auth import auth
from app.routers.vulnerabilities import vulnerabilities
from app.routers.messages import messages
from app.routers.assets import assets
from slowapi.errors import RateLimitExceeded
from app.core.rate_limit import limiter, rate_limit_exceeded_handler

# ================= CONFIGURACIÓN INICIAL =================
# Ejecutamos la función de logs que analizamos antes. 
# Si no haces esto, los logs no se guardarán en archivo.
setup_logging()

# Obtenemos el logger para este archivo.
logger = logging.getLogger(__name__)

# Creamos la instancia de la aplicación.
app = FastAPI(
    title="API de Inventario de Activos",
    description="API segura para el manejo de activos y vulnerabilidades de TI",
    version="1.0.0",
    docs_url="/docs",  # Swagger UI
    redoc_url="/redoc")

app.state.limiter = limiter # Asociamos el estado del limiter al estado en el que esté la aplicacion. Esta linea resulta crucial, pues hace que el 
                            # limiter sea accesible globalmente en toda la aplicación. Mediante esta linea, hacemos que todos los routers, con   
                            # el decorador @limiter, puedan acceder al sistema de rate limit, el cual es un sistema fundamental de seguridad
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler) # type: ignore 

#Configuración CORS
allowed_origins = os.getenv( # Creamos una variable, la cual contenga direcciones de origen permitidas para CORS, esto lo hacemos mediante 
                            # os.getenv para poder cambiar los origenes permitidos sin tocar el codigo, porque lo primero que comprueba es 
                            # si exsiste una variable de entorno allowed_origins, si es asi, toma el valor de esa variable, sino utiliza las 
                            # indicadas explicitamente
    "ALLOWED_ORIGINS",
    "http://localhost:3000, http://localhost:8000, http://localhost:80, http://localhost"
).split(",")

#limpiar espacios en blanco
allowed_origins = [origin.strip() for origin in allowed_origins]
logger.info(f"CORS allowed origins:{allowed_origins}")

# Registrar el handler de rate limit con type: ignore para resolver el problema de tipos
# exception handler es una funcion que maneja errores especificos en fastapi

app.add_middleware( # Mediante la configuracion del middleware CORS, controlamos que origenes pueden hacer peticiones y con que parametros 
    CORSMiddleware,
    allow_origins = allowed_origins, # Permitimos que se hagan peticiones desde los origenes incluidos en la variable allowed_origins
    allow_credentials = True, # Permitimos el uso de cookies y tokens de credenciales enviados por el navegador
    allow_methods=["GET","POST","PUT","DELETE", "OPTIONS"], # Declaramos los metodos HTTP permitidos  
    allow_headers = ["Authorization", "Content-Type"], # Define las cabeceras permitidas que puede enviar el cliente, # Define las cabeceras que el cliente puede leer en la respuesta
    max_age = 600 # Tiempo el cual tiene disponible el navegador para verificar la politica CORS
)

app.add_middleware(SecurityHeadersMiddleware) # Añadimos el middleware personalizado, para insertar las cabeceras de seguridad para respuestas
                                            # HTTP 

# Vemos mas adelante, un endpoint simple, de verificacion de estado de la API. Este devuelve una respuesta indicando que esta operativa, y que 
# puede procesar peticiones. 
# 
# Aunque no es parte fundamental del objetivo de la API (para lo que va a ser usada) es esencial para operaciones. Tener una forma de verificar 
# que la aplicacion esta viva, y que puede procesar informacion como debería, es esencial.
# ================= EVENTOS DEL CICLO DE VIDA =================
# @app.on_event("startup"): Este código se ejecuta UNA SOLA VEZ, justo cuando enciendes el servidor.
@app.on_event("startup")
def on_startup():
    logger.info("Iniciando API de Inventario de Activos...")
    # Llama a la función que crea las tablas en la DB si no existen.
    create_db_and_tables()
    logger.info("API preparada para recibir solicitudes")

# ================= MANEJO DE ERRORES (EXCEPTION HANDLERS) =================
# Estos bloques interceptan errores para que el usuario nunca vea un mensaje feo de código ("Internal Server Error" crudo).

# 1. Error Global (Catch-All): Atrapa cualquier crash inesperado del código.
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exec: Exception):
    # Registramos el error completo en el log para los desarrolladores.
    """
    Manejador global de excepciones no capturadas
    
    Security:
    - NO exponer stack traces al cliente
    - Logear error completo con traceback
    - Devolver mensaje genérico
    
    Referencias:
    - CWE-209: Generation of Error Message Containing Sensitive Information
    - OWASP Top 10 A09:2021 - Security Logging and Monitoring Failures
    """
    logger.error(
        f"Error inesperado en {request.method} {request.url.path}: {exec}",
        exc_info = True, # ¡IMPORTANTE! Esto guarda el "Traceback" (la pila de llamadas) en el log.
        # extra={...}: Agrega datos contextuales al log JSON.
        extra = {
            "client_host": request.client.host if request.client else "unknown",    # IP del cliente.
            "method": request.method,   # GET, POST, etc.
            "path": request.url.path,   # /users/me
            "query_params": str(request.query_params)
        }
    )
    # Al usuario le devolvemos un mensaje genérico por seguridad (no revelamos detalles del error interno).
    return JSONResponse(
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
        content = {"detail": "Error interno del servidor"}
    )

# 2. Error de Validación: Atrapa cuando Pydantic rechaza datos (ej. email mal formato).
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    app.include_router(assets.router, prefix="/assets", tags=["assets"])
    # Logueamos como WARNING (no es un error nuestro, es culpa del cliente).
    
    """
    Manejador de errores de validación de Pydantic
    
    Security:
    - Devolver errores genéricos (no exponer estructura interna)
    - Logear detalles para debugging
    """
    logger.warning(
        f"Error de validación en {request.method} {request.url.path}: {exc.errors()}",
        extra = {
            "client_host": request.client.host if request.client else "unknown",
            "errors": exc.errors()  # Detalles exactos de qué campo falló.
        }
    )
    # Devolvemos un 422 (Unprocessable Entity).
    return JSONResponse(
        status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
        content = {"detail": "Petición de datos inválida"}
    )

# 3. Error HTTP Estándar: Atrapa cuando nosotros lanzamos `raise HTTPException(...)`.
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """
    Manejador de excepciones HTTP explícitas
    
    Estas son lanzadas intencionalmente (HTTPException de FastAPI)
    """
    logger.warning(
        f"Error HTTP {exc.status_code} en {request.url.path}: {exc.detail}",
        extra = {"client_host": request.client.host if request.client else "unknown"}
    )
    # Devolvemos exactamente el código y mensaje que definimos al lanzar el error.
    return JSONResponse(
        status_code = exc.status_code,
        content = {"detail": exc.detail}
    )

# ================= RUTAS PRINCIPALES =================
# Endpoint simple para ver si el servidor está vivo (Health Check).
# Útil para balanceadores de carga o Kubernetes
@app.get("/health")
def health():
    return {"status": "ok"}

# Conectamos las "tuberías" de las otras secciones de la app.
# prefix="/auth": Todas las rutas de auth.py empezarán por /auth (ej: /auth/login).
# tags=["auth"]: Las agrupa bajo la etiqueta "auth" en la documentación visual.
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(users.router, prefix="/users", tags=["users"])
app.include_router(messages.router, prefix="/messages", tags=["messages"])
app.include_router(assets.router, prefix="/assets", tags=["assets"])
app.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])

logger.info("all routers registered")

# ================= ARRANQUE LOCAL =================
# Este bloque solo se ejecuta si corres el archivo directamente (python main.py).
if __name__ == "__main__":
    import uvicorn  # El servidor web asíncrono.
    # Arranca la app en el puerto 8000.
    # host="0.0.0.0" permite que sea visible desde otras máquinas en la red (o Docker).
    uvicorn.run(app, host="0.0.0.0", port=8000)