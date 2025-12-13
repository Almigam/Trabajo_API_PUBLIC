import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, create_engine, SQLModel
from sqlalchemy.pool import StaticPool

from app.main import app
from app.core.database import get_session
from app.models.asset import User
from app.core.security import get_password_hash

@pytest.fixture(name="session")
def session_fixture():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass = StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session

@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()

@pytest.fixture
def test_user(session: Session):
    user = User(
        username = "testuser",
        email = "test@example.com",
        hashed_password = get_password_hash("SecureP@ss123!"),
        role = "user"
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@pytest.fixture
def admin_user(session: Session):
    admin = User(
        username = "admin",
        email = "admin@example.com",
        hashed_password = get_password_hash("AdminP@ss123!"),
        role = "admin"
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)
    return admin

@pytest.fixture
def user_token (client: TestClient, test_user: User):
    response = client.post( data = {"username": "testuser", "password": "SecureP@ss123!"})
    return response.json()["access_token"]

@pytest.fixture
def admin_token(client: TestClient, admin_user: User):
    response = client.post(
        "/auth/login",
        data = {"username": "admin", "password": "AdminP@ss123!"}
    )
    return response.json()["access_token"]