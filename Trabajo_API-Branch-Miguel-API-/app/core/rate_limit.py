# El presente archivo contiene un sistema de limitacion de peticiones, mas conocido como rate limiting para nuestra API, para proteger al servidor de ataques de 
# denegacion de servicio. Esto se hace limitando la cantidad de solicitudes que puede hacer un usuario en un espacio de tiempo determinado
#
#COMPONENTES PRINCIPALES:
# 1. limiter: Es un objeto que rastrea y limita peticiones por IP a 1000 peticiones por hora
# 2. rate_limit_exceeded_handler: Es una función que maneja el error cuando se excede el límite y bloquea la solicitud que lo hace
# 3. Logger: Registra intentos de abuso para monitoreo y seguridad
#
# ESQUEMA CONCEPTUAL:
#
#   El cliente realiza una petición HTTP → el Limiter verifica límite actual del usuario y toma una decisión:
#       ├─ Si esa peticion está dentro del límite → Se procesa la petición normalmente
#       └─ Si excede el límite → se llama a rate_limit_exceeded_handler y actua → Respuesta 429 (Too Many Requests)


from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, status
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__) # Inicializamos la herramienta para crear logs

limiter = Limiter( # Inicializamos el limitador de peticiones, la pieza central del presente codigo
    key_func=get_remote_address, # Con este parametro, extraemos la IP del request, y la usamos como clave unica. Todas las requests de la misma IP, compartirán 
                                # contador, resulta esencial, pues sin este parametro, no sabriamos diferenciar de que cliente es cada request, y por tanto, 
                                # limitarlas

    default_limits=["1000/hour"]  # Definimos el limite por defecto, el formato cantidad/tiempo, es interpretado automaticamente por slowapi
)

# La siguiente funcion maneja las situaciones en las cuales un cliente excede el limite de peticiones permitidas, devolviendo al usuario una respuesta HTTP 429 
# 
# Sin esta funcion, al usuario se le devolvería un error 500 (Internal Server Error) sin ninguna informacion, con la creacion de esta funcion, devolvemos 
# informacion al usuario de porque ha fallado su request, dandole informacion como cuanto tiene que esperar hasta poder volver a mandar una request 
# 
# Ademas, con esta funcion, registramos el evento de RateLimitExceed
# 
# A esta funcion, se le pasan los parametros Request, que se trata de la peticion HTTP del usuario, y exc, la excepcion RateLimitExceeded 
# 
# Devuelve finalente una response con codigo 429 con un mensaje explicando al cliente porque ha fallado su request#

def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:

    logger.warning(f"Rate limit exceeded for {request.client.host} on {request.url.path}") # Creamos el log, con la IP del cliente que excedió el limite y 
                                                                                        # en que endpoint ha pasado. Con .warning indicamos que es un 
                                                                                        # evento que requiere atencion, pero no es critico
    
    return JSONResponse( # Una vez creado el log, pasamos a definir que se devolverá al cliente
        status_code=status.HTTP_429_TOO_MANY_REQUESTS, # Definimos que codigo de respuesta HTTP será devuelto al cliente, en este caso se devolvera el codigo 
                                                    # 429, al ser el estandar para indicar el rate limiting 
        content={ # Define mediante un diccionario (para ser serializado mas tarde a un objeto JSON) el contenido con un mensaje explicando que ha pasado
            "detail": "Too many requests. Please try again later.", # detail es el campo estandar que fastapi utiliza para los mensajes de error
            "retry_after_seconds": 60 # Campo en el que se especifica cuanto debe esperar el cliente para hacer otra request
        },
        headers={"Retry-After": "60"} # Se añade el header HTTP estandar Retry after con un valor especifico Aunque ya incluimos "retry_after_seconds" en 
                                    # el JSON, este header es el método estándar de comunicar esta información a nivel de protocolo
    )