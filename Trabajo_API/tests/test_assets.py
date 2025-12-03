import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from app.models.asset import Asset, AssetType, AssetStatus, RiskLevel, User
from app.core.security import get_password_hash

@pytest.fixture
def test_asset(session: Session, test_user: User):
    """Activo de prueba perteneciente a testuser"""
    asset = Asset(
        name="Test Server",
        asset_type=AssetType.SERVER,
        description="Test server for unit tests",
        ip_address="192.168.1.100",
        hostname="test-server-01",
        os_version="Ubuntu 22.04 LTS",
        location="Datacenter A - Rack 3",
        owner_id=test_user.id
    )
    session.add(asset)
    session.commit()
    session.refresh(asset)
    return asset

@pytest.fixture
def admin_asset(session: Session, admin_user: User):
    """Activo de prueba perteneciente a admin"""
    asset = Asset(
        name="Admin Workstation",
        asset_type=AssetType.WORKSTATION,
        description="Admin workstation",
        ip_address="192.168.1.10",
        hostname="admin-ws-01",
        owner_id=admin_user.id
    )
    session.add(asset)
    session.commit()
    session.refresh(asset)
    return asset

def test_create_asset_requires_admin(client: TestClient, user_token: str):
    """Test: Solo admin puede crear activos"""
    asset_data = {
        "name": "New Server",
        "asset_type": "server",
        "description": "Test server"
    }
    
    response = client.post(
        "/assets",
        json=asset_data,
        headers={"Authorization": f"Bearer {user_token}"}
    )
    
    assert response.status_code == 403

def test_create_asset_success(client: TestClient, admin_token: str):
    """Test: Admin puede crear activos"""
    asset_data = {
        "name": "Production Server",
        "asset_type": "server",
        "description": "Production web server",
        "ip_address": "10.0.1.50",
        "hostname": "prod-web-01",
        "os_version": "CentOS 8",
        "location": "AWS us-east-1"
    }
    
    response = client.post(
        "/assets",
        json=asset_data,
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Production Server"
    assert data["asset_type"] == "server"

def test_create_asset_invalid_ip(client: TestClient, admin_token: str):
    """Test: Validación de IP address inválida"""
    asset_data = {
        "name": "Invalid Server",
        "asset_type": "server",
        "ip_address": "999.999.999.999"
    }
    
    response = client.post(
        "/assets",
        json=asset_data,
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 422

def test_list_assets_user_sees_only_own(
    client: TestClient, 
    user_token: str, 
    test_asset: Asset,
    admin_asset: Asset
):
    """Test: Usuario normal solo ve sus propios activos"""
    response = client.get(
        "/assets",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    
    assert response.status_code == 200
    assets = response.json()
    
    # Solo debe ver test_asset, no admin_asset
    assert len(assets) == 1
    assert assets[0]["id"] == test_asset.id

def test_list_assets_admin_sees_all(
    client: TestClient, 
    admin_token: str, 
    test_asset: Asset,
    admin_asset: Asset
):
    """Test: Admin ve todos los activos"""
    response = client.get(
        "/assets",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 200
    assets = response.json()
    assert len(assets) >= 2

def test_get_asset_idor_protection(client: TestClient, user_token: str, admin_asset: Asset):
    """Test IDOR: Usuario no puede ver activo de otro usuario"""
    response = client.get(
        f"/assets/{admin_asset.id}",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    
    assert response.status_code == 403

def test_update_asset_success(client: TestClient, admin_token: str, test_asset: Asset):
    """Test: Admin puede actualizar activos"""
    response = client.put(
        f"/assets/{test_asset.id}",
        json={"name": "Updated Server Name"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 200
    assert response.json()["name"] == "Updated Server Name"

def test_delete_asset_success(client: TestClient, admin_token: str, test_asset: Asset):
    """Test: Admin puede eliminar activos"""
    response = client.delete(
        f"/assets/{test_asset.id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 204

def test_get_asset_statistics(client: TestClient, admin_token: str):
    """Test: Endpoint de estadísticas"""
    response = client.get(
        "/assets/stats",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "total_assets" in data
    assert "by_type" in data