# importaciones necesarias
from pydantic import BaseModel, Field, field_validator, EmailStr
from typing import Optional, List
from datetime import datetime
from enum import Enum
import re

#Enum para roles de usuario
class AsserTypeEnum(str, Enum): #Tipos de activos
    server = "server"
    workstation = "workstation"
    network_device = "network_device"
    application = "application"
    database = "database"
    mobile_device = "mobile_device"

class AssetStatusEnum(str, Enum): #Estados de activos
    active = "active"
    inactive = "inactive"
    maintenance = "maintenance"
    decommissioned = "decommissioned"

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

class UserOut(BaseModel):
    id: int
    username: str
    role: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class MessageCreate(BaseModel):
    content: str = Field(min_length=1, max_length=500)

class MessageOut(BaseModel):
    id: int
    content: str
    owner_id: int

    class Config:
        from_attributes = True

