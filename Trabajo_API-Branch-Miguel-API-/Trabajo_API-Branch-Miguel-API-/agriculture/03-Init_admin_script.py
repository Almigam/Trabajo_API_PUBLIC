"""
Script para crear usuario administrador inicial
Ejecutar: python scripts/init_admin.py
"""
import sys
import os

# Añadir directorio raíz al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlmodel import Session, select
from app.models.asset import User
from app.core.security import get_password_hash
from app.core.database import engine, create_db_and_tables

def create_admin_user():
    """Crear usuario admin si no existe"""
    
    # Crear tablas
    create_db_and_tables()
    
    with Session(engine) as session:
        # Verificar si ya existe
        existing = session.exec(
            select(User).where(User.username == "admin")
        ).first()
        
        if existing:
            print("✅ Admin user already exists")
            return
        
        # Crear admin
        admin = User(
            username="admin",
            email="admin@agriculture.local",
            hashed_password=get_password_hash("Admin123!@#"),
            role="admin",
            is_active=True
        )
        
        session.add(admin)
        session.commit()
        session.refresh(admin)
        
        print("✅ Admin user created successfully!")
        print(f"   Username: admin")
        print(f"   Password: Admin123!@#")
        print(f"   Email: admin@agriculture.local")
        print(f"   ID: {admin.id}")

if __name__ == "__main__":
    create_admin_user()