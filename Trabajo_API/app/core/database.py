from sqlmodel import create_engine, Session, SQLModel
from contextlib import contextmanager
import os
import logging

logger = logging.getLogger(__name__)

# Database URL desde variable de entorno
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database/data.db")

# Crear engine
engine = create_engine(
    DATABASE_URL,
    echo=False,  # No mostrar queries SQL en logs (seguridad)
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

def create_db_and_tables():
    logger.info("Creando tablas de la base de datos...")
    SQLModel.metadata.create_all(engine)
    logger.info("Tablas de la base de datos creadas correctamente")

def get_session():
    with Session(engine) as session:
        yield session

@contextmanager
def get_session_context():
    session = Session(engine)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
