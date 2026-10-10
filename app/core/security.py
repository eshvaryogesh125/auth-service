from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone

from app.core.settings import settings
import uuid

from app.core.logging import logger

ALGORITHM = "RS256"
PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return PWD_CONTEXT.hash(password)

def verify_password(plain_password: str, hashed_password) -> bool:
    return PWD_CONTEXT.verify(plain_password, hashed_password)

def create_access_token(
        subject: str,
        roles: str,
        tenant_id: str,
        jti: str,
        expires_minutes: int = None,
    ) -> str:
    
    expires_minutes = expires_minutes if expires_minutes is not None else settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=expires_minutes)

    payload = {
        "exp" : expire,
        "iat" : now,
        "type": "access",
        "jti" : jti,
        "sub" : subject,
        "tenant_id" : tenant_id, 
        "roles": roles
    }

    return jwt.encode(payload, settings.JWT_PRIVATE_KEY, ALGORITHM)

def decode_access_token(to_decode):
    try:
        decoded = jwt.decode(to_decode, settings.JWT_PUBLIC_KEY, algorithms=[ALGORITHM])
        return decoded
    except JWTError as err:
        logger.info(f"Exception at decode_access_token:{str(err)}")
        raise