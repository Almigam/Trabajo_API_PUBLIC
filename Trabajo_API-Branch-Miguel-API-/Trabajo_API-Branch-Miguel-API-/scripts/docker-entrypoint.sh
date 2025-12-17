#!/bin/bash
set -e

echo "🚀 Starting Secure API Backend..."

# Esperar a que PostgreSQL esté listo
echo "⏳ Waiting for PostgreSQL..."
while ! pg_isready -h postgres -p 5432 -U secure_api_user > /dev/null 2>&1; do
    sleep 1
done
echo "✅ PostgreSQL is ready!"

# Crear tablas y usuario admin
echo "📦 Initializing database..."
python3 -c "
from app.core.database import create_db_and_tables
from app.models.asset import User
from app.core.security import get_password_hash
from sqlmodel import Session, select, create_engine
import os

DATABASE_URL = os.getenv('DATABASE_URL')
engine = create_engine(DATABASE_URL)

# Crear tablas
create_db_and_tables()
print('✅ Tables created')

# Crear usuario admin si no existe
with Session(engine) as session:
    existing = session.exec(select(User).where(User.username == 'admin')).first()
    
    if not existing:
        admin = User(
            username='admin',
            email='admin@agriculture.local',
            hashed_password=get_password_hash('Admin123!@#'),
            role='admin',
            is_active=True
        )
        session.add(admin)
        session.commit()
        print('✅ Admin user created (username: admin, password: Admin123!@#)')
    else:
        print('ℹ️  Admin user already exists')
"

echo "🎯 Starting API server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --log-level info