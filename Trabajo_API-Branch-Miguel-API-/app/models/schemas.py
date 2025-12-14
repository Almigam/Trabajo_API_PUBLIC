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
    cve_id: str = Field(              # Se define que el campo, recibirá datos de tipo str
        min_length=9, 
        max_length=20 
        )                             # Los el rango de caracteres que tendrá el campo se configura de esa manera porque existen 2 formatos de cve_id: CVE-YYYY-N y 
                                    # CVE-YYYY-NNNNNNN dando margen de 3 caracteres por casos especiales
    
    title: str = Field( # Titulo del CVE
        min_length=5, 
        max_length=200
        )               # Rango de longitud del titulo, por la diferencia de tipos de titulos que existen, desde mas concisos hasta mas descriptivos
    
    description: str = Field( # Descripción del CVE
        min_length=10, 
        max_length=2000
        )
    
    severity: RiskLevelEnum   # Clasificacion de la peligrosidad de la vulnerabilidad creada

    cvss_score: Optional[float] = Field( # Puntuación CVSS de la vulnerabilidad
        None,                            # Campo tipo de dato del campo establecido en None por defecto (No todos los CVEs tienen puntuaciones CVSS asignadas)
        ge=0.0, 
        le=10.0
        )                                # Rango de greater or equal y less or equal
    
    published_date: datetime             # Fecha de publicacion del CVE, campo de tipo de dato datetime 

    references: Optional[str] = Field( # Urls de referencia que tienen importancia para la vulnerabilidad
        None,                          # No siempre existen referencias
        max_length=1000
        )

    @field_validator('cve_id') # Incorporamos un validador en este campo en especifico, porque existen validaciones a realizar que no podemos comprobar en Field, como
                            # el formato del ID del cve, el cual tiene un formato especifico CVE-YYYY-N o CVE-YYYY-NNNNNNN
    def validate_cve_format(cls, v):
        if not re.match(r'^CVE-\d{4}-\d{4,}$', v.upper()):                    # Cuerpo del field_validator, en este, lo que se le indica al bucle es: Si los datos 
                                                                            # introducidos por el usuario no siguen el siguiente esquema: Texto literal "CVE-" seguido
                                                                            # de 4 digitos seguido de un "-" seguido de, como minimo, otros 4 digitos(transformado todo
                                                                            # a mayusculas)
            raise ValueError('Invalid CVE ID format. Expected CVE-YYYY-NNNN') # Devuelve el siguiente error
        return v.upper()                                                      # Si coincide, devuelve los datos introducidos por el usuario con los caracteres str en  
                                                                            # mayusculas

    @field_validator('references') # De nuevo tenemos otro validator para este campo en concreto, porque en este campo deberían de haber URLs, y debemos de asegurarnos de
                                # que esto sea realmente así, y con Field no podemos hacerlo.
    def validate_references(cls, v):
        if v is None:
            return v                                                  # Si el campo es None (el campo esta vacío) acepta el valor sin validar
        
        urls = [url.strip() for url in v.split(',')]                  # Debemos entender primero, que el campo references, serán varias urls, separadas por comas, por esto, lo que estamos
                                                                    # indicando aqui es, que separe las urls que se intoduzcan, estableciendo como separador la comas 
        for url in urls:
            if not re.match(r'^https://.+\..+', url):                 # Indicamos el formato que deben de tener las URLs para que sean validas: Debe empezar com https://, continuando por 
                                                                    # uno o mas caracteres cualesquiera (.+) un punto literal (\.) y finalmente, uno o mas caracteres cualquiera 
                raise ValueError(f'Invalid URL in references: {url}') # Si no cumplen estas condiciones, devolver un error
        return v                                                      # Si coincide, devolver las urls introducidas

    
# Modelo para actualizar vulnerabilidades (todos los campos son opcionales)
class VulnerabilityUpdate(BaseModel):
    title: Optional[str] = Field(     
        None, 
        min_length=5, 
        max_length=200
        )
    
    description: Optional[str] = Field(
        None, 
        min_length=10, 
        max_length=2000
        )
    
    severity: Optional[RiskLevelEnum] = None

    cvss_score: Optional[float] = Field(
        None, 
        ge=0.0, 
        le=10.0
        )
    
    references: Optional[str] = Field(
        None, 
        max_length=1000
        )


# Modelo para devolver vulnerabilidades (salida)
class VulnerabilityOut(BaseModel):
    id: int  # ID único en la base de datos
    cve_id: str
    title: str
    severity: str
    description: str
    cvss_score: Optional[float]
    published_date: datetime
    references : Optional[str]
    created_at: datetime           # No existe en VulnerabilityCreate, porque este registro lo hace automatico la BD
    
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
