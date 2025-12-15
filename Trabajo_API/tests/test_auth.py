import httpx, pytest
from fastapi.testclient import TestClient
from app.core.security import verify_password, get_password_hash

BASE = "http://127.0.0.1:8000"

def test_password_hahsing_argon2():
    password = "SecureP@ssw0rd!"
    hashed = get_password_hash(password)
    assert hashed.startswith("$argon2id$")
    assert verify_password(password, hashed)
    assert not verify_password("WrongPassword", hashed)

def test_register_success(client: TestClient):
    response = client.post(
        "/auth/register",
        json = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "SecureP@ss123!"
        }
    )

    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "newuser@example.com"
    assert data["role"] == "user"
    assert "hashed_password" not in data

def test_register_duplicate_username(client: TestClient, test_user):
    response = client.post(
        json = {
            "username": "testuser",
            "email": "other@example.com",
            "password": "SecureP@ss123!"
        }
    )

    assert response.status_code == 400
    assert "already registered" in response.json()["detail"].lower()

def test_register_weak_password(client: TestClient):
    response = client.post(
        json = {
            "username": "newuser2",
            "email": "newuser2@example.com",
            "password": "weak"
        }
    )

    assert response.status_code == 422

@pytest.mark.asyncio
async def test_register_and_login():
    async with httpx.AsyncClient(base_url=BASE) as client:
        r = await client.post("/auth/register", json={"username":"alice","password":"Password123!"})
        assert r.status_code in (200,201)
        r = await client.post("/auth/login", data={"username":"alice","password":"Password123!"})
        assert r.status_code == 200
        token = r.json()["access_token"]
        assert token
