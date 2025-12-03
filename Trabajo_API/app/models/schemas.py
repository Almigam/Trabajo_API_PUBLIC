# Este archivo contiene los schemas de Pydantic que es una libreria utilizada para definir modelos de datos para la validacion y serializacion de los datos para la gestion de usuarios y activos en la aplicacion.

# importaciones necesarias
from pydantic import (
    BaseModel,
    Field,
    field_validator,
    EmailStr,
)  # Importar clases y funciones de Pydantic para validacion de datos
from typing import Optional, List  # Importar tipos de datos opcionales y listas
from datetime import datetime  # Importar clase datetime para manejo de fechas y horas
from enum import Enum  # Importar clase Enum para crear enumeraciones
import re  # Importar modulo de expresiones regulares para validaciones personalizadas

"""
Clases que sirven para definir enumeraciones de tipos de activos, estados y niveles de riesgo.
Estas enumeraciones ayudan a estandarizar y limitar los valores que pueden tomar ciertos campos en los modelos Pydantic.
"""


class AssetTypeEnum(
    str, Enum
):  # Con esta clase se enumeran los tipos de activos IT disponibles y luego con Pydantic se usan en los esquemas de datos
    SERVER = "server"  # Tipo de activo: servidor
    WORKSTATION = "workstation"  # Tipo de activo: workstation
    NETWORK_DEVICE = "network_device"  # "": dispositivo de red
    APPLICATION = "application"  # "": Aplicación
    DATABASE = "database"  # "": Base de datos
    MOBILE_DEVICE = "mobile_device"  # "": Movil


class AssetStatusEnum(
    str, Enum
):  # Con esta clase se enumeran los estados en los que puede estar un activo.
    ACTIVE = "active"  # Activo en uso
    INACTIVE = "inactive"  # Activo no en uso
    MAINTENANCE = "maintenance"  # En mantenimiento
    DECOMISSIONED = "decomissioned"  # Fuera de servivio/no funciona


class RiskLevelEnum(
    str, Enum
):  # Esta clase sirve para poner los niveles de riesgo que puede tener un activo IT.
    LOW = "low"  # Nivel bajo de riesgo
    MEDIUM = "medium"  # Nivel medio de riesgo
    HIGH = "high"  # Nivel alto de riesgo
    CRITICAL = "critical"  # Nivel crítico de riesgo
    pass


"""
Esta es la parte de los modelos Pydantic pero para los usuarios.
Se usan para validar y estructurar los datos que entran y salen de la API(tokens).
"""


class UserCreate(BaseModel):  # Schema para crear un usuario
    username: str = Field(
        min_length=3, max_length=50
    )  # Validacion de longitud del nombre de usuario
    email: EmailStr  # Validacion de formato de email
    password: str = Field(
        min_length=8, max_length=128
    )  # Validacion de longitud de la contraseña

    @field_validator("username")  # Validacion personalizada del nombre de usuario
    def validate_username(cls, v):  # Validar caracteres permitidos
        if not re.match(
            "^[a-zA-Z0-9_.-]+$", v
        ):  # Solo letras, numeros y caracteres _ . -
            raise ValueError(
                "Username can only contain letters, numbers, and characters: _ . -"
            )

        # Evitar nombres de usuario reservados
        forbidden = [
            "admin",
            "root",
            "system",
            "administrator",
            "user",
            "api",
        ]  # Nombres no permitidos
        if v.lower() in forbidden:
            raise ValueError("Nombre de usuario no permitido.")

        return v

    @field_validator("password")  # Validacion personalizada de la contraseña
    def validate_password(cls, v):
        if not re.search(r"[A-Z]", v):  # Al menos una letra mayuscula
            raise ValueError("La contraseña debe tener al menos una letra mayúscula.")

        if not re.search(r"[a-z]", v):  # Al menos una letra minuscula
            raise ValueError("La contraseña debe tener al menos una letra minúscula.")

        if not re.search(r"[0-9]", v):  # Al menos un numero
            raise ValueError("La contraseña debe tener al menos un número.")

        if not re.search(
            r"[!@#$%^&*(),.?\":{}|<>]", v
        ):  # Al menos un caracter especial
            raise ValueError("La contraseña debe tener al menos un carácter especial.")

        return v


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None  # Validacion de formato de email
    role: Optional[str] = Field(
        None, pattern="^(user|admin)$"
    )  # Validacion de rol, solo 'user' o 'admin' ^ y $ indican inicio y fin de cadena
    is_active: Optional[bool] = None  # Estado del usuario


class UserOut(BaseModel):  # Schema para salida de usuario
    id: int  # Identificador unico del usuario
    username: str  # Nombre de usuario
    email: EmailStr  # Email del usuario
    role: str  # Rol del usuario
    is_active: bool  # Estado del usuario
    created_at: datetime  # Fecha de creacion del usuario

    class Config:  # Configuracion para permitir conversion desde objetos ORM
        from_attributes = True  # Permitir conversion desde objetos ORM


# Schemas de Activos


class AssetCreate(
    BaseModel
):  # BaseModel es la clase base para todos los modelos de Pydantic
    """Schema para creación de activo"""

    name: str = Field(min_length=3, max_length=100)  # Nombre del activo
    asset_type: AssetTypeEnum  # Tipo de activo
    description: Optional[str] = Field(None, max_length=500)  # Descripcion del activo
    ip_address: Optional[str] = Field(None, max_length=45)  # Direccion IP del activo
    hostname: Optional[str] = Field(None, max_length=255)  # Nombre del host del activo
    os_version: Optional[str] = Field(
        None, max_length=100
    )  # Version del sistema operativo
    location: Optional[str] = Field(None, max_length=200)  # Ubicacion del activo
    owner_id: Optional[int] = (
        None  # ID del propietario del activo, si no se especifica, se asigna al creador
    )

    @field_validator("ip_address")  # Validacion personalizada de la direccion IP
    def validate_ip_address(cls, v):  # cls es la clase actual
        if v is None:  # Si no se proporciona direccion IP, no hacer nada
            return v

        # Validar formato de direccion IP (IPv4 e IPv6)
        import ipaddress  # Importar modulo ipaddress para validacion de IP

        try:
            ipaddress.ip_address(v)  # Intentar crear un objeto de direccion IP
        except ValueError:
            raise ValueError("Invalid IP address format.")  # Si falla, lanzar error
        return v

    @field_validator(
        "hostname"
    )  # Sirve para validar el nombre del host que se ingresa en el esquema de creacion de activo
    def validate_hostname(
        cls, v
    ):  # cls es la clase actual y v es el valor del nombre del host
        if v is None:  # Si no proporciona nombre del host, no se hace nada
            return v
        # Para validar el formato que tiene el nombre del host, si no cumple con el formato, se lanza el error
        if not re.match(
            # Inicio del nombre del host tiene que comenzar con una letra o numero, seguido de letras, numeros o guiones, con una longitud maxima de 63 caracteres
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
            # Luego puede tener varios segmentos separados por puntos, cada segmento siguiendo las mismas reglas
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
            # Se vuelve a llamar al valor para validar el nombre del host
            v,
        ):
            raise ValueError(
                "Invalid hostname format (RFC 1123)"
            )  # RFC1123 es el estandar para nombres de host

        if (
            len(v) > 253
        ):  # Segun RFC 1123, la longitud maxima de un nombre de host es 253 caracteres
            raise ValueError("Hostname exceeds maximum length of 253 characters.")
        return v


class AssetUpdate(
    BaseModel
):  # BaseModel es la clase base para todos los modelos de Pydantic
    """Schema para actualización de activo"""

    name: Optional[str] = Field(None, min_length=3, max_length=100)  # Nombre del activo
    asset_type: Optional[AssetTypeEnum] = None  # Tipo de activo
    description: Optional[str] = Field(None, max_length=500)  # Descripcion del activo
    ip_address: Optional[str] = Field(None, max_length=45)  # Direccion IP del activo
    hostname: Optional[str] = Field(None, max_length=255)  # Nombre del host
    os_version: Optional[str] = Field(
        None, max_length=100
    )  # Version del sistema operativo
    location: Optional[str] = Field(None, max_length=200)  # Ubicacion
    status: Optional[AssetStatusEnum] = None  # Estado del activo
    risk_level: Optional[RiskLevelEnum] = None  # Nivel de riesgo
    owner_id: Optional[int] = None  # ID del propietario del activo

    @field_validator("ip_address")  # Validacion personalizada de la direccion IP
    def validate_ip_address(cls, v):  # cls es la clase actual
        if v is None:  # Si no se proporciona direccion IP, no hacer nada
            return v

        # Validar formato de direccion IP (IPv4 e IPv6)
        import ipaddress  # Importar modulo ipaddress para validacion de IP

        try:
            ipaddress.ip_address(v)  # Intentar crear un objeto de direccion IP
        except ValueError:
            raise ValueError("Invalid IP address format.")  # Si falla, lanzar error
        return v

    @field_validator(
        "hostname"
    )  # Sirve para validar el nombre del host que se ingresa en el esquema de creacion de activo
    def validate_hostname(
        cls, v
    ):  # cls es la clase actual y v es el valor del nombre del host
        if v is None:  # Si no proporciona nombre del host, no se hace nada
            return v
        # Para validar el formato que tiene el nombre del host, si no cumple con el formato, se lanza el error
        if not re.match(
            # Inicio del nombre del host tiene que comenzar con una letra o numero, seguido de letras, numeros o guiones, con una longitud maxima de 63 caracteres
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
            # Luego puede tener varios segmentos separados por puntos, cada segmento siguiendo las mismas reglas
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
            # Se vuelve a llamar al valor para validar el nombre del host
            v,
            # No hace falta comprobar la longitud maxima aqui, porque ya se hace en la definicion del campo hostname
        ):
            raise ValueError(
                "Invalid hostname format (RFC 1123)"
            )  # RFC1123 es el estandar para nombres de host
        return v


class AssetOut(
    BaseModel
):  # BaseModel es la clase base para todos los modelos de Pydantic
    id: int  # Identificador unico del activo
    name: str  # Nombre del activo
    asset_type: AssetTypeEnum  # Tipo de activo
    description: Optional[str] = None  # Descripcion del activo
    ip_address: Optional[str] = None  # Direccion IP del activo
    hostname: Optional[str] = None  # Nombre del host
    os_version: Optional[str] = None  # Version del sistema operativo
    location: Optional[str] = None  # Ubicacion
    status: AssetStatusEnum  # Estado del activo
    risk_level: RiskLevelEnum  # Nivel de riesgo
    owner_id: int  # ID del propietario del activo
    created_at: datetime  # Fecha de creacion del activo
    updated_at: datetime  # Fecha de ultima actualizacion del activo

    class Config:  # Configuracion para permitir conversion desde objetos ORM
        from_attributes = True  # Permitir conversion desde objetos ORM


class AssetOutWithOwner(
    AssetOut
):  # Schema para salida de activo con informacion del propietario
    owner: UserOut  # Informacion del propietario del activo


class AssetStats(BaseModel):  # Schema para estadisticas de activos
    total_assets: int  # Total de activos
    by_type: dict  # Activos por tipo
    by_status: dict  # Activos por estado
    by_risk_level: dict  # Activos por nivel de riesgo
    critical_assets: int  # Activos criticos


class TokenPair(BaseModel):  # Schema para token de autenticacion
    access_token: str  # Token de acceso
    refresh_token: str  # Token de refresco
    token_type: str  # Tipo de token (ej. Bearer)
