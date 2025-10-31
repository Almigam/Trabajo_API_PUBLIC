import httpx, pytest

BASE = "http://127.0.0.1:8000"

@pytest.mark.asyncio
async def test_register_and_login():
    async with httpx.AsyncClient(base_url=BASE) as client:
        r = await client.post("/auth/register", json={"username":"alice","password":"Password123!"})
        assert r.status_code in (200,201)
        r = await client.post("/auth/login", data={"username":"alice","password":"Password123!"})
        assert r.status_code == 200
        token = r.json()["access_token"]
        assert token
