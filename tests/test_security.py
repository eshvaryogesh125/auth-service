import asyncio
import pytest
from types import SimpleNamespace
from fastapi.testclient import TestClient
from jose import jwt
from datetime import timedelta
from app.core.exceptions import (
    AccountDeactivatedError,
    AccountLockedError,
    AuthError,
    EmailAlreadyExistsError,
    EmailNotVerifiedError,
    InvalidCredentialsError,
    InvalidCurrentPasswordError,
    InvalidOrExpiredTokenError,
    TenantNotFoundError,
)
from app.core.security import create_access_token, hash_password, verify_password
from app.core.settings import settings
from app.api.v1.deps import get_client_ip
from app.core.redis import RateLimitService
from app.main import app
from app.schemas import TokenResponse
from app.services.auth_services import AuthService

def test_valid_token():
    token = create_access_token(
        subject="user-123",
        roles=["admin"],
        tenant_id="tenant-456",
        jti="jwt-1",
    )
    payload = jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=["RS256"])
    assert payload["sub"] == "user-123"
    assert payload["type"] == "access"


def test_expired_token():
    token = create_access_token(
        subject="user-123",
        roles=["admin"],
        tenant_id="tenant-456",
        jti="jwt-2",
        expires_minutes=-1,
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=["RS256"])


def test_tampered_signature():
    token = create_access_token(
        subject="user-123",
        roles=["admin"],
        tenant_id="tenant-456",
        jti="jwt-3",
    )
    tampered = token[:-10] + "tamperedXX"
    with pytest.raises(jwt.JWTError):
        jwt.decode(tampered, settings.JWT_PUBLIC_KEY, algorithms=["RS256"])


def test_proxy_ip_ignores_forwarded_headers():
    request = SimpleNamespace(
        headers={"x-forwarded-for": "203.0.113.10, 10.0.0.1"},
        client=SimpleNamespace(host="127.0.0.1"),
    )
    assert get_client_ip(request) == "127.0.0.1"


def test_custom_auth_errors_are_distinct():
    with pytest.raises(TenantNotFoundError):
        raise TenantNotFoundError()

    with pytest.raises(EmailAlreadyExistsError):
        raise EmailAlreadyExistsError()

    with pytest.raises(InvalidCredentialsError):
        raise InvalidCredentialsError()

    with pytest.raises(EmailNotVerifiedError):
        raise EmailNotVerifiedError()

    with pytest.raises(AccountDeactivatedError):
        raise AccountDeactivatedError()

    with pytest.raises(InvalidCurrentPasswordError):
        raise InvalidCurrentPasswordError()

    with pytest.raises(InvalidOrExpiredTokenError):
        raise InvalidOrExpiredTokenError()

    assert issubclass(TenantNotFoundError, AuthError)


def test_login_lockout_after_too_many_failed_attempts(monkeypatch):
    async def fake_check(prefix, identifier, limit, window):
        return False

    monkeypatch.setattr(RateLimitService, "check_and_increment", staticmethod(fake_check))

    with pytest.raises(AccountLockedError, match="account_locked"):
        asyncio.run(
            AuthService.login(
                db=None,
                email="user@example.com",
                password="bad-password",
                tenant_slug="acme",
                ip_address="203.0.113.10",
                user_agent="pytest",
            )
        )


def test_login_accepts_oauth2_form_data(monkeypatch):
    async def fake_check(prefix, identifier, limit, window):
        return True

    async def fake_login(*, db, email, password, tenant_slug, ip_address, user_agent):
        assert email == "user@example.com"
        assert password == "Pass123!"
        assert tenant_slug == "acme"
        return TokenResponse(access_token="abc", refresh_token="def")

    monkeypatch.setattr(RateLimitService, "check_and_increment", staticmethod(fake_check))
    monkeypatch.setattr(AuthService, "login", staticmethod(fake_login))

    client = TestClient(app)
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "user@example.com", "password": "Pass123!", "tenant_slug": "acme"},
    )

    assert response.status_code == 200
    assert response.json()["access_token"] == "abc"