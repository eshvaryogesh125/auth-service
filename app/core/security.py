from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta, timezone

from app.core.settings import settings


ALGORITHM = "RS256"
PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return PWD_CONTEXT.hash(password)

def verify_password(plain_password: str, hashed_password) -> bool:
    return PWD_CONTEXT.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_minutes: int = None) -> str:
    to_encode = data.copy()
    expires_minutes = expires_minutes if expires_minutes is not None else settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)

    to_encode.update({
        "exp" : expire,
        "iat" : datetime.now(timezone.utc),
        "type": "access"
    })

    return jwt.encode(to_encode, settings.JWT_PRIVATE_KEY, ALGORITHM)
