from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Response, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.v1.deps import get_current_user, get_token_payload, rate_limit
from app.models import User
from app.schemas import (
    LoginRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserRegisterRequest,
    UserRegisterResponse,
)
from app.services.auth_services import AuthService
from app.services.user_services import UserService

router = APIRouter()


@router.post("/register", response_model=UserRegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: UserRegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit),
):
    try:
        user = await UserService.register(
            db=db,
            email=body.email,
            password=body.password,
            tenant_slug=body.tenant_slug,
        )
        return UserRegisterResponse(user_id=user.id)
    except ValueError as e:
        err = str(e)
        if err == "tenant_not_found":
            raise HTTPException(status_code=404, detail="Tenant not found")
        if err == "email_already_exists":
            raise HTTPException(status_code=409, detail="Email already registered")
        raise HTTPException(status_code=400, detail=err)


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit),
):
    try:
        return await AuthService.login(
            db=db,
            email=body.email,
            password=body.password,
            tenant_slug=body.tenant_slug,
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent", ""),
        )
    except ValueError as e:
        err = str(e)
        if err == "invalid_credentials":
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if err == "email_not_verified":
            raise HTTPException(status_code=403, detail="Email not verified")
        if err == "account_deactivated":
            raise HTTPException(status_code=403, detail="Account deactivated")
        raise HTTPException(status_code=400, detail=err)


@router.post("/token/refresh", response_model=TokenResponse)
async def refresh_token(
    body: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        return await AuthService.refresh(db=db, raw_refresh_token=body.refresh_token)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


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
        raw_refresh_token=body.refresh_token,
        access_token_jti=payload["jti"],
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
        access_token_exp=exp,
    )