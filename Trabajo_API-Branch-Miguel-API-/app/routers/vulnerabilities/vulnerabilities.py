# En este archivo implementamos la capa de gestion de vulnerabilidades del sistema, incluyendo endpoints para listar, crear vincular y consultar 
# vulnerabilidades asociadas a activos. Su proposito principal es centralizar toda la logica relacionada con el ciclo de vida de las 
# vulnerabilidades. 
# 
# Se implementa tambien control de acceso para que estos endpoints solo sean accesibles por los administradores del sistema
# 
# Sus principales funcionalidades son: 
#   - Hacer consultas filtradas com paginacion para hacer consultas eficientes
#   - Creacion de nuevas vulnerabilidades con validacion previa
#   - Crear asociaciones entre vulnerabilidades y activos, para vincular estos#

from fastapi import APIRouter, Depends, HTTPException, Query, Path, status, Body
from sqlmodel import Session, select, or_
from typing import List, Optional
from datetime import datetime, timezone 
import logging

from app.models.asset import Vulnerability, Asset, AssetVulnerability, User, RiskLevel
from app.models.schemas import VulnerabilityCreate, VulnerabilityUpdate, VulnerabilityOut
from app.core.security import get_current_user, require_admin
from app.core.database import get_session

logger = logging.getLogger(__name__) # Creamos una instancia de la biblioteca logging, la cual usaremos para crear logs cuando asi lo queramos
router = APIRouter() # Este router, contendrá las rutas de los endpoints, sin ello, no podriamos definir rutas

@router.get("/", response_model=List[VulnerabilityOut]) # Definimos que esta función manejará peticiones get a la raiz de la ruta, ademas
                                                        # definimos el modelo de respuesta, es decir, la peticion será gestionada por 
                                                        # VulnerabilityOut
def list_vulnerabilities(
    skip: int = Query(0, ge=0),            # Define cuanta cantidad de información se omitirá en la peticion del usuario
    limit: int = Query(100, ge=1, le=500), # Se establece cuantos registros habrá por pagina, es decir:
                                        # Si tenemos 100 registros, y tenemos un limite de registros de 25, y definimos un skip de 50, se
                                        # le mostrará al usuario desde la segunda pagina directamente. En resumen, ambas lineas definen 
                                        # como se gestiona la paginacion en las peticiones del usuario

    severity: Optional[str] = Query(None, description="Fitrar por severidad"), # opcion de filtrar por severidad, para granular la busqueda
    search: Optional[str] = Query(None, min_length=2, description="Buscar en CVE/titulo"), # Otro filtro de busqueda, por CVE ID o titulo de vulnerabilidad
    current_user: dict = Depends(get_current_user), # Llamamos a get_current_user para obtener el usuario de quien esta haciendo la peticion, para asegurarnos de que 
                                                    # quien está haciendo dicha peticion tiene los permisos necesarios para hacerla
    session: Session = Depends(get_session) # Obtiene acceso a la base de datos, usando get_session creando una sesion a la base datos, la cual se usara como "area 
                                            # de trabajo temporal" donde podremos ir incluyendo cambios, y si hay algun error, poder solventarlo con rollback
):
    query = select(Vulnerability) # Inicia o crea la consulta SQL SELECT para la base de datos

    if severity:
        query = query.where(Vulnerability.severity == severity) # Aplicamos el filtro de severidad si se ha introducido

    if search:
        search_pattern = f"%{search}%" # Si se introduce algo en search, se declaara que se filtre por esa cadena, y mediante % declaramos que puede haber cualquier
                                    # secuencia de caracteres (incluyendo ninguno) antes o despues (%search%)
        query = query.where(
            or_(
                Vulnerability.cve_id.ilike(search_pattern),
                Vulnerability.title.ilike(search_pattern) # Consulta SQL, donde se define, que busque la cadena introducida por el usuario, ignorando que sea 
                                                        # mayuscula o no (ilike), y, que lo busque tanto en cve_id y en title(or_)
            )   
        )

    query = query.offset(skip).limit(limit) # Implementamos la paginación, con los parametros skip y limit declarados previamente
    vulns = session.exec(query).all() # Ejecuta la consulta SQL, y mediante .all se devuelven todo los resultados como una lista
                                    # Devuelve los datos, y mediante VulnerabilityOut los serializa a JSON para devolverlos al cliiente
    return vulns

@router.post("/", response_model=VulnerabilityOut, status_code= status.HTTP_201_CREATED) # Creamos la ruta del endpoint para crear vulnerabilidades, con el 
                                                                                        # status_code 201 (creado)
def create_vulnerability(
    vuln_data: VulnerabilityCreate, # Utilizamos la clase VulnerabilityCreate, donde se definen los requisitos para crear una vulnerabilidad
    current_user: dict = Depends(require_admin), # Se obtiene el usuario de quien esta creando la vulnerabilidad requiriendo que sea administrador para ello
    session: Session = Depends(get_session) # Acceso a la BD
):
    existing = session.exec(
        select(Vulnerability).where(Vulnerability.cve_id == vuln_data.cve_id)
    ).first() # Verificamos que no exsista ya una vulnerabilidad con ese CVE ID (ya existe). Mediante .first devolvemos el primer resultado (al ser CVE ID 
            # un valor unico, solo deberia salir un registro) si no existen registros con ese CVE ID se devuelve None

    if existing:
        raise HTTPException(400, f"Vulnerability {vuln_data.cve_id} already exists") # Si la respuesta no es None, se devuelve la excepcion HTTP 400 (bad
                                                                                    # request) junto con el mensaje indicado
    
    db_vuln = Vulnerability(**vuln_data.model_dump()) # Transformamos los datos de entrada  validados, en registros de base de datos, model_dump, convierte
                                                      # los datos de entrada a un diccionario y mediante ** descomponemos ese diccionario en campo-valor
    session.add(db_vuln) # Añadimos el registro a la sesion
    session.commit() # Confirmamos los cambios, y los añadimos a la BD
    session.refresh(db_vuln) # Recargamos la base de datos, para obtener tanto el ID y el timestamp (porque son autogenerados)

    logger.info(f"Admin {current_user['username']} created {db_vuln.cve_id}") # Generamos el log de creacion de vulnerabilidad.

    return db_vuln # Devolvemos la vulnerabilidad creada, a modo de comprobacion para el cliente de que se creo la vuln correctamente

# Endpoint para vincular una vulnerabilidad a un asset, utilizando AssetVulnerability
@router.post("/assets/{asset_id}/vulnerabilities/{vuln_id}", status_code=201)
def link_vulnerability_to_asset(
    asset_id: int = Path(..., gt=0),
    vuln_id: int = Path(..., gt=0), # Define que los parametros son obligatorios, y que el valor de estos deben de ser mayores que 0

    current_user: dict = Depends(require_admin),
    session: Session = Depends(get_session)
):
    # Verificamos si el asset que el usuario esta intentando relacionar con una vulnerabilidad especifica, existe
    asset = session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found") # Si no existe, lanzamos una excepcion HTTP, informando al usuario del error
    
    # Verificamos si el asset y la vulnerability especificadas por el usuario, ya se encuentran linkeadas entre ellas
    existing = session.exec(
        select(AssetVulnerability).where(
            AssetVulnerability.asset_id == asset_id,
            AssetVulnerability.vulnerability_id == vuln_id
        )
    ).first()

    if existing:
        raise HTTPException(400, "Already Linked") # si es asi, se lanza una excepcion HTTP

    # Una vez verificado, introducimos los valores a la tabla AssetVulnerability, y lo añadimos a la sesion (recodemos, que esto es temporal, todavia no esta incluido en
    # la tabla)

    link = AssetVulnerability(asset_id=asset_id, vulnerability_id=vuln_id)
    session.add(link)

    if vuln.severity == RiskLevel.CRITICAL and asset.risk_level != RiskLevel.CRITICAL:
        asset.risk_level = RiskLevel.CRITICAL # De esta manera, definimos que si el nivel de severidad de la vulnerabilidad es CRITICAL, pero el asset no tiene nivel 
                                            # de criticidad, o no es critical, automaticamente el nivel de criticidad del asset escala a critical
        asset.updated_at = datetime.now(timezone.utc)
        session.add(asset) # Añadimos a la sesion el nivel de criticidad con el timestamp de la creacion

    session.commit()

    logger.info(f"Admin {current_user['username']} linked {vuln.cve_id} to asset {asset_id}")

    return {"message": "Vulnerability linked succesfully"}

# Finalmente creamos el log, y devolvemos al cliente un mensaje, que verifica que la operacion se realizó con exito


# Endpoint para obtener las vulnerabilidades que estan asociadas a un asset (usando VulnerabilityOut como modelo de respuesta)
@router.get("/assets/{asset_id}/vulnerabilities", response_model=List[VulnerabilityOut])
def get_asset_vulnerabilities( 
    asset_id: int = Path(..., gt=0), # Parametro obligatorio, con longitud mayor que 0 
    current_user: dict = Depends(get_current_user), # Obtenemos la sesion del cliente que realiza la solicitud, para controlar sus permisos
    session: Session = Depends(get_session) # Creamos la sesion de la BD, para la consultá que realizará el cliente
):
    asset = session.get(Asset, asset_id) # Buscamos mediante el asset_id, debido que es la clave primaria de la tabla, sin esto Podríamos intentar consultar vulnerabilidades de un asset inexistente.
    if not asset:
        raise HTTPException(404, "asset not found") # Excepcion HTTP si no existe asset vinculado al asset_id entregado por el usuario
    
    if current_user["role"] != "admin":
        user = session.exec(
            select(User).where(User.username == current_user["username"])
        ).first() # Tenemos una parte esencial de la seguridad de este endpoint en este bloque de codigo, pues estamos realizando una verificacion de que solo el usuario dueño del asset que se esta solicitando pueda ver las vulnerabilidades que este tiene (siempre que el user no sea un admin)

        if asset.owner_id != user.id:
            raise HTTPException(403, "Access denied") # Si no coinciden asset.owner_id y user.id se prohibe el acceso al usuario que esta realizando dicha consulta 
        
    # Finalmente si asset.owner_id y user.id coinciden, se hace la consulta SQL, y devolvemos todos los resultados de la consulta 
    vulns = session.exec(
        select(Vulnerability)
        .join(AssetVulnerability)
        .where(AssetVulnerability.asset_id == asset_id)
        .order_by(Vulnerability.severity.desc())
    ).all()

    return vulns # Devolvemos al usuario los resultados de la consulta SQL