from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging
from app.core.logging_config import setup_logging
from app.core.database import create_db_and_tables
from app.routers.users import users
from app.routers.auth import auth
from app.routers.messages import messages

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title="API de Inventario de Activos",
    description="API segura para el manejo de activos y vulnerabilidades de TI",
    version="1.0.0",
    docs_url="/docs",  # Swagger UI
    redoc_url="/redoc")


@app.on.event("startup")
def on_startup():
    logger.info("Iniciando API de Inventario de Activos...")
    create_db_and_tables()
    logger.info("API preparada para recibir solicitudes")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exec: Exception):
    logger.error(
        f"Error inesperado en {request.method} {request.url.path}: {exec}",
        exc_info = True
        extra = {
            "client_host": request.client.host if request.client else "unknown",
            "method": request.method,
            "path": request.url.path,
            "query_params": str(request.query_params)
        }
    )
    return JSONResponse(
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
        content = {"detail": "Error interno del servidor"}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.warning(
        f"Error de validación en {request.method} {request.url.path}: {exc.errors()}",
        extra = {
            "client_host": request.client.host if request.client else "unknown",
            "errors": exc.errors()
        }
    )

    return JSONResponse(
        status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
        content = {"detail": "Petición de datos inválida"}
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    logger.warning(
        f"Error HTTP {exc.status_code} en {request.url.path}: {exc.detail}",
        extra = {"client_host": request.client.host if request.client else "unknown"}
    )

    return JSONResponse(
        status_code = exc.status_code,
        content = {"detail": exc.detail}
    )

@app.get("/health")
def health():
    return {"status": "ok"}

app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(users.router, prefix="/users", tags=["users"])
app.include_router(messages.router, prefix="/messages", tags=["messages"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)