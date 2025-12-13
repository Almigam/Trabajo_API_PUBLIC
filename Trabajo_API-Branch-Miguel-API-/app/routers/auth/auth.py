from fastapi import APIRouter, HTTPException, Request, Depends, Body, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select, SQLModel, create_engine
from typing import Dict
from app.models.asset import User
from app.models.schemas import UserCreate, UserOut, Token
from app.core.security import get_password_hash, verify_password, create_access_token, create_refresh_token, decode_token, get_current_user
from app.core.database import get_session
from app.core.rate_limit import limiter, RateLimitExceeded
from app.main import limiter
import os
import logging


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database/data.db") # Obtiene la URL de la base de datos, para almacenamiento de credenciales
engine = create_engine(DATABASE_URL, echo=False) # Crea el motor de la base de datos, sin logs de debug, debido a que ya tenemos configurado 
                                                # nuestro propio sistema de loging, por lo cual, evitamos ruido innecesario
# Asegura que las tablas exsistan, si no existen, las crea crea las tablas (para un correcto arranque del sistema)
SQLModel.metadata.create_all(engine)
# Configuración del logger para este archivo.
logger = logging.getLogger(__name__)

# Creamos el Router. En el archivo main.py principal, seguramente harás algo como:
# app.include_router(auth_router)
router = APIRouter()

# ================= RUTA: REGISTRO =================
# @router.post: Define que esta función responde a peticiones HTTP POST en "/register".
# response_model=UserOut: Filtra la respuesta. Aunque creemos un usuario con password, 
# el modelo 'UserOut' se asegura de devolver solo los datos públicos (id, email, username) y no el hash.
@router.post("/register", response_model=UserOut, status_code=201)
@limiter.limit(RATE_LIMITS["auth_register"])
def register(user: UserCreate, session: Session = Depends(get_session)):
    # user: UserCreate -> FastAPI valida que el JSON recibido cumpla las reglas (largo, caracteres, etc).
    # session: Session -> FastAPI inyecta una conexión activa a la DB.
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
    # 1. Verificar si el username ya existe.
    # session.exec(select(...)): Ejecuta una consulta SQL SELECT * FROM user WHERE ...
    existing_user = session.exec(
        select(User).where(User.username == user.username)
    ).first()   # .first() devuelve el primer resultado o None.
    
    # Si existe, lanzamos error 400 (Bad Request).
    if existing_user:
        logger.warning(f"Registration attempt with existing username: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # 2. Verificar si el email ya existe (misma lógica).
    existing_email = session.exec(
        select(User).where(User.email == user.email)
    ).first()
    
    if existing_email:
        logger.warning(f"Registration attempt with existing email: {user.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # 3. Crear el objeto Usuario para la base de datos.
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=get_password_hash(user.password),
        #role="user"
    )
    
    # 4. Guardar en DB.
    session.add(db_user)    # Marca el objeto para ser guardado.
    session.commit()        # Ejecuta la transacción SQL (INSERT INTO...).
    session.refresh(db_user)    # Recarga el objeto desde la DB para obtener el ID autogenerado.
    
    logger.info(f"New user registered: {user.username} (ID: {db_user.id})")
    
    # Devolvemos el objeto. FastAPI filtrará los campos usando 'response_model=UserOut'.
    return db_user

# ================= RUTA: LOGIN =================
# Devuelve un TokenPair (access + refresh).
@router.post("/login", response_model=Token)
@limiter.limit(RATE_LIMITS["auth_login"])
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    # form_data: Recibe los datos del formulario estándar (username, password).
    """
    Iniciar sesión con username/password
    
    Devuelve:
    - access_token: JWT válido por 15 minutos
    - refresh_token: JWT válido por 7 días
    
    Security:
    - Rate limited: 5 intentos/minuto (implementado en main.py)
    - Mensajes de error genéricos (no revelar si username existe)
    - Logging de intentos fallidos
    """
    # Buscamos al usuario por nombre.
    user = session.exec(select(User).where(User.username == form_data.username)).first()
    # Verificamos dos cosas:
    # 1. ¿Existe el usuario? (if not user)
    # 2. ¿Coincide la contraseña? (verify_password usa Argon2 para comparar)
    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning(
            f"Failed login attempt for username: {form_data.username}", 
            extra={
                "username": form_data.username,
                "client_host": request.client.host
                }
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Bloqueo extra: Si el usuario existe pero está marcado como inactivo (soft delete).    
    if not user.is_active:
        logger.warning(f"Logint attempt for inactive account: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account inactive",
        )
    # Preparamos los datos mínimos para meter dentro del token.
    token_data = {"sub": user.username, "role": user.role}
    # Generamos los dos tokens criptográficos.
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    logger.info(f"Usuario logueado exitosamente: {user.username} (role: {user.role})")

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type ="bearer"
    ) 
    # Devolvemos el JSON con los tokens.
    # ERROR --> return Token(access_token=access_token, refresh_token=refresh_token)

# ================= RUTA: REFRESH TOKEN =================
# Esta ruta se usa cuando el Access Token caduca (pasan los 15 min).
@router.post("/refresh", response_model=Dict[str, str])
@limiter.limit(RATE_LIMITS["auth_refresh"])
def refresh_access_token(refresh_token: str = Body(..., embed=True), session: Session = Depends(get_session)):
    # Body(..., embed=True): Espera un JSON así: { "refresh_token": "el_token_largo..." }
    """
    Renovar access token usando refresh token
    
    Flow:
    1. Cliente detecta que access token expirará pronto
    2. Envía refresh token
    3. Backend valida y genera nuevo access token
    4. Cliente actualiza token sin interrumpir sesión
    
    Security:
    - Valida que el token sea de tipo "refresh"
    - Verifica que el usuario aún exista y esté activo
    - No renueva el refresh token (usar rotation en producción)
    """
    try:
        # Decodificamos el token (verifica firma y expiración de 7 días).
        payload = decode_token(refresh_token)
        
        # Seguridad extra: asegurar que NO estamos intentando usar un Access Token para refrescar.
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        # Extraemos datos.
        username = payload.get("sub")
        role = payload.get("role", "user")
        
        # Validamos contra la base de datos por si el usuario fue borrado en los últimos días.
        user = session.exec(
            select(User).where(User.username == username)
        ).first()
        
        if not user or not user.is_active:
            logger.warning(f"Refresh attempt for non-existent/inactive user: {username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Creamos UNICAMENTE un nuevo access token. 
        # (Opcionalmente podrías rotar también el refresh token aquí para máxima seguridad).
        new_access_token = create_access_token({"sub": username, "role": role})
        
        logger.info(f"Token refreshed for user: {username}")
        
        return {
            "access_token": new_access_token,
            "token_type": "bearer"
        }
        
    except HTTPException:
        raise   # Si ya lanzamos un error HTTP arriba, déjalo pasar.
    except Exception as e:
        logger.error(f"Error refreshing token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

# ================= RUTA: LOGOUT =================
# Nota: JWT es "stateless". El servidor no "recuerda" sesiones abiertas.
# El logout real consiste en que el Frontend (Cliente) borre el token de su memoria.
# Este endpoint es más simbólico o para logs, a menos que implementes una "lista negra" de tokens en DB.
@router.post("/logout")
def logout(current_user: dict = Depends(get_current_user)):
    """
    Cerrar sesión
    
    En esta implementación es stateless (solo logging).
    
    En producción:
    - Añadir token a blacklist (Redis)
    - Revocar refresh token
    - Invalidar sesiones activas
    """
    logger.info(f"User {current_user['username']} logged out")
    return {"message": "Logout succesfull"}

# ================= RUTA: ME (PERFIL) =================
# Devuelve los datos del usuario logueado actualmente.
@router.get("/me", response_model=UserOut)
def get_current_user_info(current_user: dict = Depends(get_current_user), session: Session = Depends(get_session)):
    # 1. 'get_current_user' valida el token del header Authorization y devuelve el dict básico.
    
    # 2. Hacemos query a DB para obtener los detalles frescos (email, fecha creación, etc).
    """
    Obtener información del usuario actual
    
    Útil para que el frontend verifique el token y obtenga datos actualizados
    """
    user = session.exec(select(User).where(User.username == current_user["username"])).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    return user

@router.post("/register", response_model=UserOut, status_code=201) # Creamos el endpoint de register
@limiter.limit("3/hour") # Limitamos la cantidad de llamadas
def register(request: Request, user: UserCreate, session: Session = Depends(get_session)): # Con session: Session = Depends(get_session) creamos 
                                                                                        # una sesion a la base de datos, utilizando la funcion
                                                                                        # get_session. Con esto podremos: hacer consultas,
                                                                                        # inserciones, acutalizaciones etc.... sobre la
                                                                                        # base de datos
    with Session(engine) as session: # Abre una sesion temporal con la base de datos
        exists = session.exec(select(User).where(User.username == user.username)).first() # Consulta si ya existe l username introducido
        if exists:
            raise HTTPException(status_code=400, detail="Username already registered") # Si existe, lanza una excepcion HTTP, indicando que 
                                                                                    # el username introducido ya existe

        db_user = User(username=user.username, hashed_password=get_password_hash(user.password), email=user.email) # Si por el contrario, el username no existe, se 
                                                                                            # crea el usuario y se guarda el hash de la 
                                                                                            # contraseña en vez de la contraseña en si 
                                                                                            # por seguridad
        session.add(db_user) # Añade el registro a la sesion
        session.commit() # Guarda los cambios en la BD
        session.refresh(db_user) # Recarga para obtener valores auto generados como el ID y el timestamp
        return db_user # Finalmente devuelve el usuario recien creado al cliente

# Mediante el endpoint de login, autenticamos al usuario, y generamos su token JWT. Una vez validado el username y la password, devolvemos 
# un token de tipo bearer

@router.post("/login", response_model=Token) # Creamos el endpoint de login 
@limiter.limit("5/minute") # Añadimos rate limiting

def login(request: Request, 
            form_data: OAuth2PasswordRequestForm = Depends(), # Mediante OAuth2PasswordRequestForm, 
                                                            # extraemos las credenciales introducidas 
                                                            # por el cliente en el login 
            session: Session = Depends(get_session)): 
    
    with Session(engine) as session: # Abrmimos la sesion de la BD
        db_user = session.exec(select(User).where(User.username == form_data.username)).first() # Busca el usuario introducido por el cliente en 
                                                                                                # la base de datos por username
        if not db_user or not verify_password(form_data.password, db_user.hashed_password): # Declaramos que si no coinciden, o la verificacion del 
                                                                                            # username o de la contraseña, se devuelva un error
                                                                                            # con codigo HTTP 401, indicando que se han introducido
                                                                                            # credenciales incorrectas
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        token = create_access_token({"sub": db_user.username, "role": db_user.role}) # Si todo es correcto creamos el token JWT para el usuario, 
                                                                                    # indicando para que usuario va a ser el token y que rol tiene 

        return {"access_token": token, "token_type": "bearer"} # Finalmente se devuelve el token, en forma de diccionario, que será convertido
                                                            # a JSON automaticamente por FastApi, dandole el token creado en la linea anterior
                                                            # acompañado de que tipo de token es el que se entrega al usuario, en este caso
                                                            # un bearer