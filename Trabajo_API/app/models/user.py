from sqlmodel import SQLModel, Field, Relationship
from typing import Optional, List

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str
    role: str = Field(default="user")
    messages: List["Message"] = Relationship(back_populates="owner")

class Message(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    content: str
    owner_id: int = Field(foreign_key="user.id")
    owner: Optional[User] = Relationship(back_populates="messages")
