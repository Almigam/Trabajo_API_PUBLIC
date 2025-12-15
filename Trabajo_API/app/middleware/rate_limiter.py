"""
Rate Limiting para proteger endpoints críticos

Referencias:
- OWASP API Security Top 10 (API4:2023 - Unrestricted Resource Consumption)
- CWE-307: Improper Restriction of Excessive Authentication Attempts
"""

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request, Response
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)

# Crear limiter global
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000/hour"],  # Límite global por defecto
    storage_uri="memory://"  # En producción usar Redis: "redis://localhost:6379"
)

# Configuraciones de rate limit por endpoint
RATE_LIMITS = {
    "auth_login": "5/minute",      # Login: 5 intentos por minuto
    "auth_register": "3/minute",   # Registro: 3 por minuto
    "auth_refresh": "10/minute",   # Refresh: 10 por minuto
    "api_general": "60/minute",    # Endpoints generales: 60 por minuto
    "api_intensive": "20/minute"   # Operaciones intensivas: 20 por minuto
}

async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """
    Handler personalizado para errores de rate limit
    
    Devuelve respuesta 429 con información útil para el cliente
    """
    client_host = request.client.host if request.client else "uknown"
    
    logger.warning(
        f"Rate limit exceeded for {client_host} on {request.url.path}",
        extra={
            "client_host": client_host,
            "path": request.url.path,
            "method": request.method
        }
    )
    
    return JSONResponse(
        status_code=429,
        content={
            "error": "Too Many Requests",
            "detail": "Rate limit exceeded. Please try again later.",
            "retry_after": str(exc.detail).split("Retry after ")[1] if "Retry after" in str(exc.detail) else "60 seconds"
        },
        headers={
            "Retry-After": "60",
            "X-RateLimit-Limit": str(exc.detail).split(" per ")[0].split("Rate limit ")[1] if "per" in str(exc.detail) else "Unknown",
        }
    )


