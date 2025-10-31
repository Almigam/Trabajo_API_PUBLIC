from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import SQLModel, create_engine, Session, select
from app.models.user import User
from app.models.schemas import UserOut
from app.core.security import require_role
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database/data.db")
engine = create_engine(DATABASE_URL, echo=False)

# Ensure tables exist
SQLModel.metadata.create_all(engine)

router = APIRouter()

@router.get("/", dependencies=[Depends(require_role("admin"))], response_model=list[UserOut])
def list_users():
    with Session(engine) as session:
        users = session.exec(select(User)).all()
        return users
