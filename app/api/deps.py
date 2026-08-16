from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload 

from app.core.database import get_db_session as get_db
from app.core.security import decode_access_token
from app.core.redis import BlacklistTokenService
from app.models.user import User, UserRole


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


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

    if user_id is None or jti is None:
        raise credentials_exception

    if await BlacklistTokenService.is_blacklisted(jti):
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