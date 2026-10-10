from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Response, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.v1.deps import get_current_user, get_client_ip, get_token_payload, rate_limit
from app.core.exceptions import (
    AccountDeactivatedError,
    AccountLockedError,
    AuthError,
    EmailAlreadyExistsError,
    EmailNotVerifiedError,
    InvalidCredentialsError,
    InvalidTokenError,
    TenantNotFoundError,
    TokenReuseDetectedError,
)
from app.models import User
from app.schemas import (
    LoginRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserRegisterRequest,
    UserRegisterResponse,
)
from app.services.auth_services import AuthService
from app.services.email_services import get_email_service
from app.services.user_services import UserService

router = APIRouter()


@router.post("/register", response_model=UserRegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: UserRegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit(3, 3600, "ip")),
):
    try:
        email_service = get_email_service()
        user = await UserService.register(
            db=db,
            email_service = email_service,
            email=body.email,
            password=body.password,
            tenant_slug=body.tenant_slug,
        )
        return UserRegisterResponse(user_id=user.id)
    except TenantNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Tenant not found") from exc
    except EmailAlreadyExistsError as exc:
        raise HTTPException(status_code=409, detail="Email already registered") from exc
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def _parse_login_request(request: Request) -> LoginRequest:
    content_type = request.headers.get("content-type", "")

    if "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        email = form.get("username") or form.get("email")
        password = form.get("password")
        tenant_slug = form.get("tenant_slug")

        if email is None or password is None or tenant_slug is None:
            raise HTTPException(status_code=422, detail="Missing required login fields")

        return LoginRequest(email=email, password=password, tenant_slug=tenant_slug)

    body = await request.json()
    return LoginRequest(**body)


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit(10, 900, "ip")),
):
    body = await _parse_login_request(request)

    try:
        return await AuthService.login(
            db=db,
            email=body.email,
            password=body.password,
            tenant_slug=body.tenant_slug,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
        )
    except InvalidCredentialsError as exc:
        raise HTTPException(status_code=401, detail="Invalid credentials") from exc
    except EmailNotVerifiedError as exc:
        raise HTTPException(status_code=403, detail="Email not verified") from exc
    except AccountDeactivatedError as exc:
        raise HTTPException(status_code=403, detail="Account deactivated") from exc
    except AccountLockedError as exc:
        raise HTTPException(status_code=429, detail="Too many failed login attempts") from exc
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/token/refresh", response_model=TokenResponse)
async def refresh_token(
    body: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        return await AuthService.refresh(db=db, raw_refresh_token=body.refresh_token)
    except (TokenReuseDetectedError, InvalidTokenError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    body: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    payload: dict = Depends(get_token_payload),
):
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    await AuthService.logout(
        db=db,
        user_id=str(current_user.id),
        raw_refresh_token=body.refresh_token,
        access_token_jti=payload["jti"],
        access_token_sid=payload.get("sid"),
        access_token_exp=exp,
    )


@router.post("/logout/all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    payload: dict = Depends(get_token_payload),
):
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
    await AuthService.logout_all(
        db=db,
        user_id=str(current_user.id),
        access_token_jti=payload["jti"],
        access_token_sid=payload.get("sid"),
        access_token_exp=exp,
    )