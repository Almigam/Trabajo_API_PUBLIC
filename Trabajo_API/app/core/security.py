from datetime import datetime, timedelta
from typing import Optional, Dict
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
import os
import secrets
import logging

logger = logging.getLogger(__name__)

# La configuración
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

# Usamos Argon2 Password Hasher que es el recomendado según OWASP

ph = PasswordHasher(
    time_cost=2,    # Iteraciones (OWASP: 2-3)
    memory_cost=65536,  # 64 MB (OWASP: 64MB mínimo)
    parallelism=4,  # Hilos paralelos
    hash_len=32,    # Longitud del hash
    salt_len=16     # Longitud de la sal
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

class TokenData(BaseModel):
    sub: Optional[str] = None
    role: Optional[str] = "user"
    token_type: Optional[str] = "access"

class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        # Intentar verificar con Argon2
        ph.verify(hashed_password, plain_password)
        
        # Verificar si necesita rehash (parámetros desactualizados)
        if ph.check_needs_rehash(hashed_password):
            logger.info("La contraseña del hash necesita rehash (parámetros desactualizados)")
            # En producción: actualizar hash en DB aquí
        
        return True
        
    except VerifyMismatchError:
        return False
        
    except InvalidHashError:
        # Hash no es Argon2, intentar bcrypt (migración)
        logger.warning("Hash bcrypt detectado, intentando verificación legacy")
        from passlib.context import CryptContext
        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        if pwd_context.verify(plain_password, hashed_password):
            logger.info("Verificación legacy bcrypt exitosa - debería rehashear")
            # En producción: actualizar a Argon2 en próximo login
            return True
        
        return False

def get_password_hash(password: str) -> str:
    return ph.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.debug(f"Creado el access token para el usuario: {data.get('sub')}")
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Tipo de token inválido"
        )
    
    username: str = payload.get("sub")
    role: str = payload.get("role", "user")
    
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Payload de token inválido"
        )
    
    return {"username": username, "role": role}

def require_role(role: str):
    def checker(user = Depends(get_current_user)):
        if user["role"] != role:
            raise HTTPException(status_code=403, detail="Privilegios insuficientes")
        return user
    return checker

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    })
    
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.debug(f"Creado el refresh token para el usuario: {data.get('sub')}")
    
    return encoded_jwt

def decode_token(token: str) -> Dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
        
    except jwt.ExpiredSignatureError:
        logger.warning("El token ha expirado")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="El token ha expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    except JWTError as e:
        logger.error(f"Error al decodificar JWT: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No se pudieron validar las credenciales",
            headers={"WWW-Authenticate": "Bearer"},
        )

def require_admin(user: Dict = Depends(get_current_user)) -> Dict:
    if user["role"] != "admin":
        logger.warning(f"El usuario {user['username']} intentó realizar una acción de administrador sin privilegios")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Privilegios de administrador requeridos"
        )
    return user