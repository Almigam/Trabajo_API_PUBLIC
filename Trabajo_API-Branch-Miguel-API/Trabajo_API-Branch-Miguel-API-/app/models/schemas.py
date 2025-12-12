#Este archivo contiene los schemas de Pydantic que es una libreria utilizada para definir modelos de datos para la validacion y serializacion de los datos para la gestion de usuarios y activos en la aplicacion.


# importaciones necesarias
from pydantic import BaseModel, Field, field_validator, EmailStr # Importar clases y funciones de Pydantic para validacion de datos
from typing import Optional, List # Importar tipos de datos opcionales y listas
from datetime import datetime # Importar clase datetime para manejo de fechas y horas
from enum import Enum  # Importar clase Enum para crear enumeraciones
import re # Importar modulo de expresiones regulares para validaciones personalizadas

#Enum para roles de usuario
class AssetTypeEnum(str, Enum): #Tipos de activos Enum es una clase base para crear enumeraciones
    server = "server" #Tipo de activo: servidor
    workstation = "workstation" #Tipo de activo: estación de trabajo
    network_device = "network_device" #Tipo de activo: dispositivo de red
    application = "application" #Tipo de activo: aplicación
    database = "database" #Tipo de activo: base de datos
    mobile_device = "mobile_device" #Tipo de activo: dispositivo móvil

class AssetStatusEnum(str, Enum): #Enumerar los estados de activos
    active = "active" #Activo
    inactive = "inactive" #Inactivo
    maintenance = "maintenance" #Mantenimiento
    decommissioned = "decommissioned" #Fuera de servicio

class RiskLevelEnum(str, Enum): #Niveles de riesgo
    low = "low" 
    medium = "medium"
    high = "high"
    critical = "critical"
    
#Schemas para la gestion de usuarios y mensajes

class UserCreate(BaseModel): #Schema para crear un usuario
    username: str = Field(min_length=3, max_length=50) # Validacion de longitud del nombre de usuario
    email: EmailStr # Validacion de formato de email
    password: str = Field(min_length=8, max_length=128) # Validacion de longitud de la contraseña
    
    @field_validator('username') # Validacion personalizada del nombre de usuario
    def validate_username(cls, v): # Validar caracteres permitidos
        if not re.match("^[a-zA-Z0-9_.-]+$", v): # Solo letras, numeros y caracteres _ . -
            raise ValueError("Username can only contain letters, numbers, and characters: _ . -")
        
        # Evitar nombres de usuario reservados
        forbidden = ['admin', 'root', 'system','administrator', 'user', 'api'] # Nombres no permitidos
        if v.lower() in forbidden: 
            raise ValueError('Nombre de usuario no permitido.')
        
        return v

    @field_validator('password') # Validacion personalizada de la contraseña
    def validate_password(cls, v):
        if not re.search(r"[A-Z]", v): # Al menos una letra mayuscula
            raise ValueError("La contraseña debe tener al menos una letra mayúscula.")
        
        if not re.search(r"[a-z]", v): # Al menos una letra minuscula
            raise ValueError("La contraseña debe tener al menos una letra minúscula.")
        
        if not re.search(r"[0-9]", v): # Al menos un numero
            raise ValueError("La contraseña debe tener al menos un número.")
        
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v): # Al menos un caracter especial
            raise ValueError("La contraseña debe tener al menos un carácter especial.")
        
        return v
    
class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None # Validacion de formato de email
    role: Optional[str] = Field(None, pattern="^(user|admin)$") # Validacion de rol, solo 'user' o 'admin' ^ y $ indican inicio y fin de cadena
    is_active: Optional[bool] = None # Estado del usuario

class UserOut(BaseModel): #Schema para salida de usuario
    id: int # Identificador unico del usuario
    username: str # Nombre de usuario
    email: EmailStr # Email del usuario
    role: str # Rol del usuario
    is_active: bool # Estado del usuario
    created_at: datetime # Fecha de creacion del usuario

    class Config: # Configuracion para permitir conversion desde objetos ORM
        from_attributes = True # Permitir conversion desde objetos ORM
    
#Schemas de Activos

class AssetCreate(BaseModel): #BaseModel es la clase base para todos los modelos de Pydantic
    name: str = Field(min_length=3, max_length=100) # Nombre del activo
    asset_type: AssetTypeEnum # Tipo de activo
    description: Optional[str] = Field(None, max_length=500) # Descripcion del activo
    ip_address: Optional[str] = Field(None, max_length=45) # Direccion IP del activo
    hostname: Optional[str] = Field(None, max_length=255) # Nombre del host del activo
    os_version: Optional[str] = Field(None, max_length=100) # Version del sistema operativo
    location: Optional[str] = Field(None, max_length=200) # Ubicacion del activo
    owner_id: Optional[int] = None # ID del propietario del activo, si no se especifica, se asigna al creador


    @field_validator('ip_address') # Validacion personalizada de la direccion IP
    def validate_ip_address(cls, v): #cls es la clase actual
        if v is None: # Si no se proporciona direccion IP, no hacer nada
            return v
        
        # Validar formato de direccion IP (IPv4 e IPv6)
        import ipaddress # Importar modulo ipaddress para validacion de IP
        try:
            ipaddress.ip_address(v) # Intentar crear un objeto de direccion IP
        except ValueError:
            raise ValueError("Invalid IP address format.") # Si falla, lanzar error
        return v

class AssetUpdate(BaseModel): #BaseModel es la clase base para todos los modelos de Pydantic
    name: Optional[str] = Field(None, min_length=3, max_length=100) # Nombre del activo
    asset_type: Optional[AssetTypeEnum] = None # Tipo de activo
    description: Optional[str] = Field(None, max_length=500) # Descripcion del activo
    ip_address: Optional[str] = Field(None, max_length=45) # Direccion IP del activo
    hostname: Optional[str] = Field(None, max_length=255) # Nombre del host
    os_version: Optional[str] = Field(None, max_length=100) # Version del sistema operativo
    location: Optional[str] = Field(None, max_length=200) # Ubicacion
    status: Optional[AssetStatusEnum] = None # Estado del activo
    risk_level: Optional[RiskLevelEnum] = None # Nivel de riesgo
    owner_id: Optional[int] = None # ID del propietario del activo

class AssetOut(BaseModel): #BaseModel es la clase base para todos los modelos de Pydantic
    id: int # Identificador unico del activo
    name: str # Nombre del activo
    asset_type: AssetTypeEnum # Tipo de activo
    description: Optional[str] = None # Descripcion del activo
    ip_address: Optional[str] = None # Direccion IP del activo
    hostname: Optional[str] = None # Nombre del host
    os_version: Optional[str] = None # Version del sistema operativo
    location: Optional[str] = None # Ubicacion
    status: AssetStatusEnum # Estado del activo
    risk_level: RiskLevelEnum # Nivel de riesgo
    owner_id: int # ID del propietario del activo
    created_at: datetime # Fecha de creacion del activo
    updated_at: datetime # Fecha de ultima actualizacion del activo

    class Config: # Configuracion para permitir conversion desde objetos ORM
        from_attributes = True # Permitir conversion desde objetos ORM
    
class AssetOutWithOwner(AssetOut): #Schema para salida de activo con informacion del propietario
    owner: UserOut # Informacion del propietario del activo

class AssetStats(BaseModel): #Schema para estadisticas de activos
    total_assets: int # Total de activos
    by_type: dict # Activos por tipo
    by_status: dict # Activos por estado
    by_risk_level: dict # Activos por nivel de riesgo
    critical_assets: int # Activos criticos
    
class Token(BaseModel): #Schema para token de autenticacion
    access_token: str # Token de acceso
    refresh_token: str # Token de refresco
    token_type: str # Tipo de token (ej. Bearer)

class MessageCreate(BaseModel):  # Schema de entrada para crear un mensaje
    content: str = Field(        # Contenido del mensaje enviado por el usuario
        min_length=1,            # Debe tener al menos 1 carácter (evita mensajes vacíos)
        max_length=500           # Máximo 500 caracteres (control de longitud razonable)
    )

class MessageOut(BaseModel):     # Schema de salida/lectura de mensaje (lo que devuelve la API)
    id: int                      # Identificador único del mensaje (autoincremental en DB, normalmente)
    content: str                 # Contenido del mensaje ya almacenado
    owner_id: int                # ID del usuario/propietario que creó el mensaje
    created_at: datetime         # Marca de tiempo de creación (UTC recomendado)

    class Config:                # Configuración de Pydantic para mapeo desde ORM/atributos
        from_attributes = True


# Modelo para detectar y añadir las vulnerabilidades del json de la parte de red.
class VulnerabilityCreate(BaseModel):
    # Identificador CVE con validación de formato 
    cve_id: str = Field(min_length=5, max_length=50, pattern=r"^CVE-\d{4}-\d+$") 
    severity: str = Field(pattern="^(low|medium|high|critical)$")           
    # Descripción detallada de la vulnerabilidad
    description: str = Field(min_length=10, max_length=1000)
    # Componente afectado (máx. 200 caracteres)
    affected_component: str = Field(max_length=200)
    # ID del activo afectado (opcional)
    asset_id: Optional[int] = None
    # Estado de la vulnerabilidad con valor por defecto "open"
    status: str = Field(default="open", pattern="^(open|patched|mitigated|accepted)$")
    # Validador adicional para el campo cve_id
    @field_validator('cve_id')
    def validate_cve_format(cls, v):
        # Comprueba que el CVE empiece por 'CVE-'
        if not v.startswith('CVE-'):
            raise ValueError("CVE ID must start with 'CVE-'")
        # Devuelve el valor en mayúsculas
        return v.upper()
    
# Modelo para actualizar vulnerabilidades (todos los campos son opcionales)
class VulnerabilityUpdate(BaseModel):
    severity: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    description: Optional[str] = Field(None, max_length=1000)
    status: Optional[str] = Field(None, pattern="^(open|patched|mitigated|accepted)$")
    notes: Optional[str] = Field(None, max_length=2000)


# Modelo para devolver vulnerabilidades (salida)
class VulnerabilityOut(BaseModel):
    id: int  # ID único en la base de datos
    cve_id: str
    severity: str
    description: str
    affected_component: str
    asset_id: Optional[int]
    status: str
    discovered_at: datetime  # Fecha de descubrimiento
    patched_at: Optional[datetime] = None  # Fecha de parcheo (opcional)
    
    # Configuración para permitir crear el modelo desde atributos ORM
    class Config:
        from_attributes = True

# Modelo para estadísticas de vulnerabilidades
class VulnerabilityStats(BaseModel):
    total_vulnerabilities: int  # Total de vulnerabilidades
    by_severity: dict           # Conteo por severidad
    by_status: dict             # Conteo por estado
    critical_open: int          # Número de críticas abiertas
    average_patch_time_days: Optional[float] = None  # Tiempo medio de parcheo
