from uuid import UUID

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload 

from app.core.settings import settings
from app.core.database import get_db
from app.core.security import decode_access_token, ALGORITHM
from app.core.redis import BlacklistTokenService, RateLimitService
from app.models.user import User, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_client_ip(request: Request) -> str:
    client = request.client
    if client and client.host:
        return client.host
    return "unknown"


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    
    credentials_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = "Could not verify credentials",
        headers = {"WWW-Authenticate": "Bearer"}   
    )

    try:
        payload = decode_access_token(token)
    except JWTError:
        raise credentials_exception

    user_id : str | None = payload.get("sub")
    jti : str | None = payload.get("jti")
    sid : str | None = payload.get("sid")

    if user_id is None or jti is None:
        raise credentials_exception

    if await BlacklistTokenService.is_blacklisted(jti):
        raise credentials_exception

    if sid is not None and await BlacklistTokenService.is_blacklisted(sid, namespace="sid"):
        raise credentials_exception

    try:
        user_uuid = UUID(user_id)
    except ValueError:
        raise credentials_exception

    result = await db.execute(
        select(User)
        .options(selectinload(User.user_roles).selectinload(UserRole.role))
        .where(User.id == user_uuid))
    user = result.scalar_one_or_none()

    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail = "Account is not active"
        )

    return user

def require_role(role: str):
    async def checker(user: User = Depends(get_current_user)):
        if role not in user.roles:
            raise HTTPException(403)
        return user
    return checker

def rate_limit(limit: int, window: int, prefix: str):
    async def checker(request: Request):
        email = None
        content_type = request.headers.get("content-type", "")

        if "application/x-www-form-urlencoded" in content_type:
            form = await request.form()
            email = form.get("username") or form.get("email")

        if not email and "application/json" in content_type:
            try:
                data = await request.json()
                email = (data or {}).get("email") or (data or {}).get("username")
            except Exception:
                email = None

        if prefix == "ip":
            identifier = get_client_ip(request)
        else:
            identifier = (email or get_client_ip(request)).lower()

        allowed = await RateLimitService.check_and_increment(prefix, identifier, limit, window)
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests"
            )
    return checker

async def get_token_payload(request: Request) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise credentials_exception
    
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise credentials_exception
