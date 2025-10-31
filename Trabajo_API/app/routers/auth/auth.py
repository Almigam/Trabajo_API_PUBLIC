from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import SQLModel, create_engine, Session, select
from app.models.user import User
from app.models.schemas import UserCreate, UserOut, Token
from app.core.security import get_password_hash, verify_password, create_access_token
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database/data.db")
engine = create_engine(DATABASE_URL, echo=False)

# Ensure tables exist
SQLModel.metadata.create_all(engine)

router = APIRouter()

@router.post("/register", response_model=UserOut, status_code=201)
def register(user: UserCreate):
    with Session(engine) as session:
        exists = session.exec(select(User).where(User.username == user.username)).first()
        if exists:
            raise HTTPException(status_code=400, detail="Username already registered")
        db_user = User(username=user.username, hashed_password=get_password_hash(user.password))
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
        return db_user

@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    with Session(engine) as session:
        db_user = session.exec(select(User).where(User.username == form_data.username)).first()
        if not db_user or not verify_password(form_data.password, db_user.hashed_password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token = create_access_token({"sub": db_user.username, "role": db_user.role})
        return {"access_token": token, "token_type": "bearer"}
