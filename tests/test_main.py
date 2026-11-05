from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "ClaimMesh"}

def test_info():
    response = client.get("/info")
    assert response.status_code == 200
    data = response.json()
    assert "project" in data
    assert "version" in data