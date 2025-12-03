from fastapi import APIRouter, HTTPException, Depends, Body, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select
from typing import Dict
from app.models.asset import User
from app.models.schemas import UserCreate, UserOut, TokenPair
from app.core.security import get_password_hash, verify_password, create_access_token, create_refresh_token, decode_token, get_current_user
from app.core.database import get_session
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/register", response_model=UserOut, status_code=201)
def register(user: UserCreate, session: Session = Depends(get_session)):
    """
    Registrar nuevo usuario
    
    Validaciones automáticas (Pydantic):
    - Username: 3-50 chars, alfanumérico
    - Email: formato válido
    - Password: 8+ chars, mayúsculas, minúsculas, números, símbolos
    
    Security:
    - Password hasheada con Argon2id
    - Rate limited (implementado en main.py)
    """
    # Verificar username único
    existing_user = session.exec(
        select(User).where(User.username == user.username)
    ).first()
    
    if existing_user:
        logger.warning(f"Intento de registro con nombre de usuario existente: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nombre de usuario ya registrado"
        )
    
    # Verificar email único
    existing_email = session.exec(
        select(User).where(User.email == user.email)
    ).first()
    
    if existing_email:
        logger.warning(f"Intento de registro con email existente: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email ya registrado"
        )
    
    # Crear usuario con Argon2
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=get_password_hash(user.password)
    )
    
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    
    logger.info(f"Nuevo usuario registrado: {user.username} (ID: {db_user.id})")
    
    return db_user

@router.post("/login", response_model=TokenPair)
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    with Session() as session:
        user = session.exec(select(User).where(User.username == form_data.username)).first()
        if not user or not verify_password(form_data.password, user.hashed_password):
            logger.warning(f"Fallo de login para usuario: {form_data.username}", extra={"username": form_data.username})
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        if not user.is_active:
            logger.warning(f"Intento de login con cuenta inactiva: {user.username}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cuenta inactiva",
            )
        token_data = {"sub": user.username, "role": user.role}
        access_token = create_access_token(token_data)
        refresh_token = create_refresh_token(token_data)

        logger.info(f"Usuario logueado exitosamente: {user.username} (role: {user.role})")

        return TokenPair(access_token=access_token, refresh_token=refresh_token)

@router.post("/refresh", response_model=Dict[str, str])
def refresh_access_token(refresh_token: str = Body(..., embed=True), session: Session = Depends(get_session)):
try:
    payload = decode_token(refresh_token)
        
    # Validar tipo de token
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type"
        )
        
    username = payload.get("sub")
    role = payload.get("role", "user")
        
    # Verificar que el usuario siga existiendo y activo
    user = session.exec(
        select(User).where(User.username == username)
    ).first()
        
    if not user or not user.is_active:
        logger.warning(f"Refresh attempt for non-existent/inactive user: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
        
    # Crear nuevo access token
    new_access_token = create_access_token({"sub": username, "role": role})
        
    logger.info(f"Token refreshed for user: {username}")
        
    return {
        "access_token": new_access_token,
        "token_type": "bearer"
    }
        
except HTTPException:
    raise
except Exception as e:
    logger.error(f"Error refreshing token: {e}")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid refresh token"
    )

@router.get("/logout")
def logout(current_user: dict = Depends(get_current_user)):
    logger.info(f"Usuario {current_user['username']} ha cerrado sesión")
    return {"message": "Logout exitoso"}

@router.get("/me", response_model=UserOut)
def get_current_user_info(current_user: dict = Depends(get_current_user), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == current_user["username"])).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    return user