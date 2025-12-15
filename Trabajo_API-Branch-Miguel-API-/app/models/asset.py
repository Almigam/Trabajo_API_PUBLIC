"""Archivo para definir los modelos de datos relacionados con los activos IT en la aplicación."""

from sqlmodel import SQLModel, Field, Relationship
from typing import Optional, List
from datetime import datetime, timezone
from enum import Enum

"""
Las clases de abajo definen los diferentes tipos de activos IT, sus estados y niveles de riesgo.
Estas enumeraciones ayudan a estandarizar y limitar los valores que pueden tomar ciertos campos en el modelo Asset.
"""


class AssetType(str, Enum):  # Enumera los tipos de activos IT disponibles
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    APPLICATION = "application"
    DATABASE = "database"
    MOBILE_DEVICE = "mobile_device"


class AssetStatus(str, Enum):  # Enumera los estados del ciclo de vida del activo
    ACTIVE = "active"
    INACTIVE = "inactive"
    MAINTENANCE = "maintenance"
    DECOMMISSIONED = "decommissioned"


class RiskLevel(str, Enum):  # Enumera los niveles de riesgo del activo
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


"""Aqui se define el modelo que tiene un usuario cualquiera de la API, 
similar al modelo en user.py pero adaptado a las necesidades de los activos IT.

Clase que representa al usuario.
SQLModel sirve para definir los modelos de datos y table= True indica que se guarda en forma de una tabla en una base de datos"""

class User(SQLModel, table=True):
    id: Optional[int] = Field(
        default=None, primary_key=True
    )  # Id del usuario, tiene un valor único gracias a primary_key=True
    username: str = Field(
        index=True, unique=True, max_length=50, min_length=3
    )  # Nombre de usuario, debe ser único y tiene restricciones de longitud
    email: str = Field(
        unique=True, max_length=255, index=True
    )  # Correo electrónico del usuario, también debe ser único y tiene restricciones de longitud
    hashed_password: str = Field(
        max_length=255
    )  # Contraseña hasheada del usuario, con restricción de longitud
    is_active: bool = Field(default=True)  # Indica si el usuario está activo o no
    role: str = Field(default="user", max_length=20) # Rol atribuido a un usuario
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )  # Fecha y hora de creación del usuario, se establece automáticamente al crear el registro, usando datetime.now con zona horaria UTC
    # Para relacionar un usuario con sus propios activos:
    assets: List["Asset"] = Relationship(
        back_populates="owner"
    )  # Relación uno a muchos con el modelo Asset, indicando que un usuario puede tener múltiples activos
    #Para relacionar un usuario con sus propios mensajes
    messages: List["Message"] = Relationship(
        back_populates="owner"
    )  # Relación uno a muchos con el modelo Message, indicando que un usuario puede tener múltiples mensajes

class Message(SQLModel, table=True):
    id: Optional[int] = Field(
        default=None, primary_key=True
    )  # Id del mensaje, tiene un valor único gracias a primary_key=True
    content: str = Field(
        max_length=500
    )  # Contenido del mensaje, con restricción de longitud máxima
    owner_id: int = Field(
        foreign_key="user.id", index=True
    )  # ID del usuario propietario, clave foránea a la tabla 'user' e indexada
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )  # Fecha y hora de creación del mensaje, usando la hora UTC actual como valor por defecto
    # Para relacionar un mensaje con su usuario propietario:
    owner: Optional[User] = Relationship(
        back_populates="messages"
    )  # Relación muchos a uno con el modelo User, indicando que muchos mensajes pueden pertenecer a un usuario


"""Aqui se define el modelo que tiene un activo cualquiera que la API maneja,
similar al modelo en user.py pero adaptado a las necesidades de los activos IT."""

class Asset(SQLModel, table=True):
    id: Optional[int] = Field(
        default=None, primary_key=True
    )  # Id del activo, tiene un valor único gracias a primary_key=True
    name: str = Field(
        max_length=100, index=True
    )  # Nombre del activo, requerido, con restricción de longitud e indexado
    asset_type: AssetType  # Tipo de activo, usando la enumeración AssetType que esta definida arriba
    description: Optional[str] = Field(
        default=None, max_length=500
    )  # Descripción del activo, campo opcional con restricción de longitud
    ip_address: Optional[str] = Field(
        default=None, max_length=45, index=True
    )  # Dirección IP del activo, campo opcional con restricción de longitud y indexado para búsquedas rápidas
    hostname: Optional[str] = Field(
        default=None, max_length=255, index=True
    )  # Nombre del host del activo, campo opcional con restricción de longitud y indexado para búsquedas rápidas
    os_version: Optional[str] = Field(
        default=None, max_length=100
    )  # Versión del sistema operativo del activo, campo opcional con restricción de longitud
    location: Optional[str] = Field(
        default=None, max_length=200
    )  # Ubicación física o lógica del activo, campo opcional con restricción de longitud
    status: AssetStatus = Field(
        default=AssetStatus.ACTIVE
    )  # Estado actual del activo, usando la enumeración AssetStatus con un valor por defecto de ACTIVO
    risk_level: RiskLevel = Field(
        default=RiskLevel.LOW
    )  # Nivel de riesgo asociado al activo, usando la enumeración RiskLevel con un valor por defecto de BAJO
    owner_id: int = Field(
        foreign_key="user.id", index=True
    )  # ID del usuario propietario, clave foránea a la tabla 'user' e indexada
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )  # Fecha y hora de creación del registro, usando la hora UTC actual como valor por defecto
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )  # Fecha y hora de la última actualización del registro, usando la hora UTC actual como valor por defecto
    # Para relacionar un activo con su propio usuario propietario:
    owner: Optional[User] = Relationship(
        back_populates="assets"
    )  # Relación muchos a uno con el modelo User, indicando que muchos activos pueden pertenecer a un usuario

class AssetVulnerability(SQLModel, table=True): # Creamos una clase, la cual crea una tabla en la base de datos

    __tablename__ = "asset_vulnerability"        # Nombramos la tabla

    asset_id: Optional[int] = Field(
        default=None,
        foreign_key="asset.id",
        primary_key=True
    )

    vulnerability_id: Optional[int] = Field( # Exactamente igual que en la clase anterior, se crea el campo, con su validación de entrada, su asignacion de tipo de
                                            # dato por defecto, una FK y se establece, tamien, como PK, para poder llevar a cabo la funcionalidad de la tabla N:N
        default=None,
        foreign_key="vulnerability.id",
        primary_key=True
    )

    detected_at: datetime = Field(      # Creamos un nuevo campo, que almacenará datos de tipo fecha y hora
        default_factory=datetime.utcnow # Si al crear el objeto, manualmente no se le da un valor, se llama a datetime.utcnow para que asigne automaticamente el valor
        )                               # con la fecha y la hora exactas en las que el objeto fue creado.
    
    status: str = Field(    # Otro campo, el cual soportará strings
        default="Open"      # Se asigna el valor OPEN directamente si no se especifica manualmente otro valor
        )
    
    notes: Optional[str] = Field( # Campo notes, que acepta tanto strings como NONE
        default = None,           # Valor por defecto
        max_length = 500          # Se establece una longitud maxima para este campo, que en este caso, no supere los 500 caracteres
        )
    
# Creamos otra clase, en la cual se define la tabla de vulnerabilidades que puedan existir en el sistema, su funcionalidad principal es almacenar información detallada
# de estas vulnerabilidades, que despues será utilizada por la tabla AssetVulnerability para correlacionar activos y vulnerabilidades.
# 
# Se trata de una tabla normal, es decir, en este caso no vamos a tener una tabla con relaciones many to many.
#
#  La creacion de esta tabla y la configuracion de sus campos, se hará de la misma forma que en AssetVulnerability
class Vulnerability(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    cve_id: str = Field(unique=True, max_length=20, index=True)
    title: str = Field(max_length=200)
    description: str = Field(max_length=2000)
    severity: RiskLevel = Field(default=RiskLevel.MEDIUM)
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    published_date: datetime
    references: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Relación many-to-many con Asset
    assets: List[Asset] = Relationship(
        back_populates="vulnerabilities",
        link_model=AssetVulnerability
    )