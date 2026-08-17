import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password, verify_password
from app.core.redis import SingleUseTokenService
from app.models.user import User
from app.models.tenant import Tenant
from app.services.email_services import EmailService
from app.core.logging import logger
from app.core.settings import settings

EMAIL_VERIFY_TTL_SECONDS = 60 * 60 * 24  # 24h

class UserService:

    @staticmethod
    async def register(
        db: AsyncSession,
        email_service: EmailService,
        email: str,
        password: str,
        tenant_slug: str,
    ) -> User:

        result = await db.execute(select(Tenant).where(Tenant.tenant_slug == tenant_slug))
        tenant = result.scalar_one_or_none()

        if not tenant:
            raise ValueError("Invalid Tenant")

        user_exists = await db.execute(select(User).where(User.tenant_id == tenant.id, User.email == email))
        user_exists = user_exists.scalar_one_or_none()
        if user_exists:
            raise ValueError("User Alreayd Registered")

        user = User(
            email=email,
            tenant_id=tenant.id,
            hashed_password=hash_password(password),
            is_verified=False,
            is_active=True
        )

        db.add(user)
        await db.flush()

        token = str(uuid.uuid4())
        await SingleUseTokenService.create("emailverify",str(user.id),token,ttl=EMAIL_VERIFY_TTL_SECONDS)

        await email_service.send(
            to=user.email,
            subject="Verify your Email",
            body=f"Click to verify: {settings.BASE_URL}/verify?token={token}"
        )

        await db.commit()
        logger.info("User Registered", extra={"user_id": str(user.id), "tenant": tenant_slug})
        return user

    @staticmethod
    async def verify_email(db:AsyncSession, token:str) -> None:

        user_id = await SingleUseTokenService.consume("emailverify", token)
        if not user_id:
            raise ValueError("Invalid or Expired token")

        result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
        user = result.scalar_one_or_none()
        if not user:
            raise ValueError("User not found")

        user.is_verified = True
        await db.commit()
        logger.info("email_verified", extra={"user_id": user_id})

    @staticmethod
    async def change_password(db: AsyncSession, user:User, current_password:str, new_password:str) -> None:

        if not verify_password(current_password, user.hashed_password):
            raise ValueError("Current password incorrect")

        user.hashed_password = hash_password(new_password)
        await db.commit()
        logger.info("password_changed", extra={"user_id": str(user.id)})
