# Este archivo contiene pruebas para la gestión de activos en la API.

import pytest
from httpx import AsyncClient

@pytest.mark.asyncio # Prueba asíncrona con pytest, mark especifica que es asíncrona y asyncio la ejecuta.
async def test_user_can_only_see_own_assets(client: AsyncClient): # Prueba asíncrona para verificar que un usuario normal solo puede ver sus propios activos.
    """
    Test IDOR: Usuario normal solo ve sus activos.
    """
    
    # Crear dos usuarios normales
    await client.post("/auth/register", json={ # Registro de usuario Alice
        "username": "alice", # Nombre de usuario
        "email": "alice@example.com", # Correo electrónico
        "password": "SecureP@ss1!" # Contraseña segura
    })
    
    await client.post("/auth/register", json={ # Registro de usuario Bob
        "username": "bob", # Nombre de usuario
        "email": "bob@example.com", # Correo electrónico
        "password": "SecureP@ss2!" # Contraseña segura
    })
    
    # Login como Alice (debe ser admin para crear activos)
    #... (crear activos como admin) ...
    
    # Login como Alice (Usuario normal)
    response = await client.post("/auth/login", data={ # Inicio de sesión de Alice
        "username": "alice", # Nombre de usuario
        "password": "SecureP@ss1!" # Contraseña
    })
    alice_token = response.json()["access_token"] # Obtener token de acceso de Alice
    
    #Login como Bob
    response = await client.post("/auth/login", data={ # Inicio de sesión de Bob
        "username": "bob", # Nombre de usuario
        "password": "SecureP@ss2!" # Contraseña
    })
    bob_token = response.json()["access_token"] # Obtener token de acceso de Bob
    
    # Bob intenta acceder a los activos de Alice (debe fallar)
    response = await client.get( # Intento de Bob de acceder al activo de Alice
        "/assets/1", # Suponiendo que el ID del activo de Alice es 1
        headers={"Authorization": f"Bearer {bob_token}"} # Autorización con token de Bob
    )
    assert response.status_code == 403 # Verificar que el acceso es prohibido
    
@pytest.mark.asyncio #Prueba asíncrona con pytest
async def test_admin_can_see_all_assets(client: AsyncClient, admin_token: str): # Prueba asíncrona para verificar que un admin puede ver todos los activos.
    """
    Test RBAC: Admin puede ver todos los activos.
    """
    response = await client.get( # Solicitud para obtener todos los activos
        "/assets/", # Endpoint de activos
        headers={"Authorization": f"Bearer {admin_token}"} # Autorización con token de admin
    )
    
    assert response.status_code == 200 # Verificar que la solicitud fue exitosa
    assets = response.json() # Obtener la lista de activos
    assert isinstance(assets, list) # Verificar que la respuesta es una lista
    
@pytest.mark.asyncio # Prueba asíncrona con pytest
async def test_create_asset_requires_admin(client: AsyncClient, user_token: str): # Prueba asíncrona para verificar que solo un admin puede crear activos.
    """
    Test: Solo admin puede crear activos.
    """
    asset_data = { # Datos del activo a crear
        "name": "Test Server", # Nombre del activo
        "asset_type": "server", # Tipo de activo
        "description": "Test server description" # Descripción del activo
    }
    
    response = await client.post( # Solicitud para crear un nuevo activo
        "/assets/", # Endpoint de activos
        json=asset_data, # Datos del activo en formato JSON
        headers={"Authorization": f"Bearer {user_token}"} # Autorización con token de usuario normal
    )
    assert response.status_code == 403 # Verificar que la creación del activo fue prohibida
    
@pytest.mark.asyncio # Prueba asíncrona con pytest
async def test_ip_address_validation(client: AsyncClient, admin_token: str): # Prueba asíncrona para validar el formato de la dirección IP al crear un activo.
    """
    Test: Validación de formato IP
    """
    
    #IP inválida
    asset_data = { # Datos del activo con IP inválida
        "name": "Test Server", # Nombre del activo
        "asset_type": "server", # Tipo del activo
        "ip_address": "999.999.999.999", # Dirección IP inválida
    }
    
    response = await client.post( # Solicitud para crear un nuevo activo
        "/assets/", # Endpoint de activos
        json=asset_data, # Datos del activo en formato JSON
        headers={"Authorization": f"Bearer {admin_token}"} # Autorización con token de admin
    )
    assert response.status_code == 422 # Verificar que la solicitud fue rechazada por formato inválido
    
    
@pytest.mark.asyncio # Prueba asíncrona con pytest
async def test_asset_statistics(client: AsyncClient, admin_token: str): # Prueba asíncrona para verificar la generación de estadísticas de activos.
    """
    Test: Estadísticas de activos
    """
    
    response = await client.get( # Solicitud para obtener estadísticas de activos
        "/assets/stats", # Endpoint de estadísticas de activos
        headers={"Authorization": f"Bearer {admin_token}"} # Autorización con token de admin
    )
    
    assert response.status_code == 200 # Verificar que la solicitud fue exitosa
    stats = response.json() # Obtener las estadísticas
    assert "total_assets" in stats # Verificar que las estadísticas contienen el total de activos
    assert "by_type" in stats # Verificar que las estadísticas contienen activos por tipo
    assert "critical_assets" in stats # Verificar que las estadísticas contienen activos críticos