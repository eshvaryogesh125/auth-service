import pytest
from jose import jwt
from datetime import timedelta
from app.core.security import create_access_token, hash_password, verify_password
from app.core.settings import settings

def test_valid_token():
    data = {"sub": "user-123", "tenant_id": "tenant-456"}
    token = create_access_token(data)
    payload = jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=["RS256"])
    assert payload["sub"] == "user-123"
    assert payload["type"] == "access"

def test_expired_token():
    data = {"sub": "user-123"}
    token = create_access_token(data, expires_minutes=-1)
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=["RS256"])

def test_tampered_signature():
    data = {"sub": "user-123"}
    token = create_access_token(data)
    tampered = token[:-10] + "tamperedXX"
    with pytest.raises(jwt.JWTError):
        jwt.decode(tampered, settings.JWT_PUBLIC_KEY, algorithms=["RS256"])