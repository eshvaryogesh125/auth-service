import uuid

from sqlalchemy import select, update
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password, verify_password
from app.core.redis import SingleUseTokenService
from app.core.exceptions import (
    EmailAlreadyExistsError,
    InvalidCurrentPasswordError,
    InvalidOrExpiredTokenError,
    TenantNotFoundError,
    UserNotFoundError,
)
from app.models import User, Tenant, UserRole
from app.services.auth_services import AuthService
from app.services.email_services import EmailService
from app.core.logging import logger
from app.core.settings import settings
from app.tasks.email_tasks import send_password_reset_email

EMAIL_VERIFY_TTL_SECONDS = 60 * 60 * 24  # 24h
PASSWORD_RESET_TTL_SECONDS = 15 * 60  # 15m

class UserService:

    @staticmethod
    async def register(
        db: AsyncSession,
        email_service: EmailService,
        email: str,
        password: str,
        tenant_slug: str,
    ) -> User:

        normalized_email = email.strip().lower()
        tenant_slug = tenant_slug.strip()

        result = await db.execute(select(Tenant).where(Tenant.slug == tenant_slug))
        tenant = result.scalar_one_or_none()

        if not tenant:
            raise TenantNotFoundError()

        user_exists = await db.execute(select(User).where(User.tenant_id == tenant.id, User.email == normalized_email))
        user_exists = user_exists.scalar_one_or_none()
        if user_exists:
            raise EmailAlreadyExistsError()

        user = User(
            email=normalized_email,
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
            raise InvalidOrExpiredTokenError()

        result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
        user = result.scalar_one_or_none()
        if not user:
            raise UserNotFoundError()

        user.is_verified = True
        await db.commit()
        logger.info("email_verified", extra={"user_id": user_id})

    @staticmethod
    async def change_password(db: AsyncSession, user:User, current_password:str, new_password:str) -> None:

        if not verify_password(current_password, user.hashed_password):
            raise InvalidCurrentPasswordError()

        user.hashed_password = hash_password(new_password)
        await AuthService.revoke_all_sessions(db=db, user_id=str(user.id))
        await db.commit()
        logger.info("password_changed", extra={"user_id": str(user.id)})

    @staticmethod
    async def request_password_reset(
        db: AsyncSession,
        email_service: EmailService,
        email: str,
        tenant_slug: str,
    ):

        normalized_email = email.strip().lower()
        tenant_result = await db.execute(
            select(Tenant).where(Tenant.slug == tenant_slug)
        )
        tenant = tenant_result.scalar_one_or_none()
        if not tenant:
            logger.warning("password_reset_unknown_tenant", extra={"tenant_slug": tenant_slug, "email": normalized_email})
            return None

        user_result = await db.execute(
            select(User).where(User.email == normalized_email, User.tenant_id == tenant.id)
            .options(selectinload(User.user_roles).selectinload(UserRole.role))
        )
        user = user_result.scalar_one_or_none()
        if not user:
            logger.warning("password_reset_unknown_user", extra={"tenant_slug": tenant_slug, "email": normalized_email})
            return None

        token = str(uuid.uuid4())
        await SingleUseTokenService.create("pwreset",str(user.id),token,ttl=PASSWORD_RESET_TTL_SECONDS)

        send_password_reset_email.delay(
            to=user.email,
            subject="Password Reset Request",
            body=f"Click to Reset Password: {settings.BASE_URL}/password-reset/confirm?token={token}",
        )
        logger.info("request_password_reset", extra={"user_id": str(user.id)})
        return user

    @staticmethod
    async def confirm_password_request(db:AsyncSession, token:str, new_password:str):

        user_id = await SingleUseTokenService.consume("pwreset", token)
        if not user_id:
            raise InvalidOrExpiredTokenError()

        result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
        user = result.scalar_one_or_none()
        if not user:
            raise UserNotFoundError()

        user.hashed_password = hash_password(new_password)
        await AuthService.revoke_all_sessions(db=db, user_id=str(user.id))
        await db.commit()  

        logger.info("confirm_password_request", extra={"user_id": str(user.id)})
