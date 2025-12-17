# ============================================
# STAGE 1: Builder
# ============================================
FROM python:3.12-slim as builder

# Metadatos
LABEL maintainer="tu-email@example.com"
LABEL description="API REST de Gestión de Activos IT - Programación Segura"

# Variables de entorno para Python
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Instalar dependencias del sistema necesarias
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    postgresql-client \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio de trabajo
WORKDIR /build

# Copiar requirements
COPY requirements.txt .

# Instalar dependencias de Python
RUN pip install --user --no-cache-dir -r requirements.txt

# ============================================
# STAGE 2: Runtime
# ============================================
FROM python:3.12-slim

# Variables de entorno
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/home/appuser/.local/bin:$PATH

# Instalar solo runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Crear usuario no-root
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app /app/logs /app/reports /app/database && \
    chown -R appuser:appuser /app

# Establecer directorio de trabajo
WORKDIR /app

# Copiar dependencias instaladas del stage builder
COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local

# Copiar código de la aplicación
COPY --chown=appuser:appuser ./app ./app
COPY --chown=appuser:appuser ./scripts ./scripts

# Crear directorios necesarios
RUN mkdir -p logs reports database && \
    chown -R appuser:appuser logs reports database

# Cambiar a usuario no-root
USER appuser

# Exponer puerto
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Script de inicio
COPY --chown=appuser:appuser docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

ENTRYPOINT ["/app/docker-entrypoint.sh"]