import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.logging import logger
from app.core.redis import RateLimitService, BlacklistTokenService
from app.core.security import create_access_token, verify_password
from app.core.settings import settings
from app.models import RefreshToken, TokenFamily, Tenant, User
from app.schemas import TokenResponse

class AuthService:

    @staticmethod
    async def revoke_all_sessions(db:AsyncSession, user_id: str) -> None:

        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=func.now())
        )
        logger.info("all_sessions_revoked", extra={"user_id": str(user_id)})

    @staticmethod
    async def login(
        db: AsyncSession,
        email: str,
        password: str,
        tenant_slug: str,
        ip_address: str,
        user_agent: str
    ) -> TokenResponse:

        tenant_result = await db.execute(
            select(Tenant).where(Tenant.slug == tenant_slug)
        )
        tenant = tenant_result.scalar_one_or_none()
        if not tenant:
            raise ValueError("invalid_credentials")


        user_result = await db.execute(
            select(User).where(User.email == email, User.tenant_id == tenant.id)
            .options(selectinload(User.roles))
        )
        user = user_result.scalar_one_or_none()

        dummy_hash = "$2b$12$KIXtCnPOLlRnXsOaJCDkAOlQEFTMv9MzBpA1lS1fWqR6YKcE3SiSO"
        candidate_hash = user.hashed_password if user else dummy_hash
        valid = verify_password(password, candidate_hash)

        if not user or not valid:
            logger.warning("login_failed", extra={"email": email, "tenant_slug": tenant_slug, "ip": ip_address})
            raise ValueError("invalid_credentials")

        
        if not user.is_verified:
            raise ValueError("email_not_verified")
        if not user.is_active:
            raise ValueError("account_deactivated")

        family_id = str(uuid4())

        db.add(
            TokenFamily(family_id=family_id, user_id=user.id, status="active")
        )

        result = await AuthService._issue_token_pair(
            db, user, tenant.id, family_id, {"ip": ip_address, "user_agent": user_agent}
        )
        await db.commit()
        
        logger.info("login_success", extra={"user_id":str(user.id),"tenant_id":str(tenant.id),"ip":ip_address})

        return result

    @staticmethod
    async def refresh(
        db: AsyncSession,
        raw_refresh_token: str,
    ) -> TokenResponse:
        
        token_hash = hashlib.sha256(raw_refresh_token.encode()).hexdigest()

        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )
        token_row = result.scalar_one_or_none()

        if not token_row:
            raise ValueError("invalid_token")

        family_result = await db.execute(
            select(TokenFamily).where(TokenFamily.family_id == token_row.family_id)
        )
        family = family_result.scalar_one_or_none()

        if not family or family.status == "compromised":
            raise ValueError("invalid_token")

        if token_row.revoked_at is not None:
            await db.execute(
                update(TokenFamily)
                .where(TokenFamily.family_id == token_row.family_id)
                .values(status="compromised")
            )
            await db.execute(
                update(RefreshToken)
                .where(
                    RefreshToken.family_id == token_row.family_id,
                    RefreshToken.revoked_at.is_(None),
                )
                .values(revoked_at=func.now())
            )
            await db.commit()
            logger.warning("refresh_token_reuse_detected", extra={"family_id": str(token_row.family_id)})
            raise ValueError("token_reuse_detected")

        if token_row.expires_at < datetime.now(timezone.utc):
            raise ValueError("token_expired")

        token_row.revoked_at = func.now()

        user_result = await db.execute(
            select(User)
            .where(User.id == token_row.user_id)
            .options(selectinload(User.roles))
        )
        user = user_result.scalar_one_or_none()
        if not user or not user.is_active:
            raise ValueError("invalid_token")

        result = await AuthService._issue_token_pair(
            db, user, token_row.tenant_id, token_row.family_id, token_row.device_info
        )

        await db.commit()
        
        logger.info("token_refreshed", extra={"user_id": str(user.id), "family_id": str(token_row.family_id)})

        return result


    @staticmethod
    async def logout(
        db:AsyncSession,
        raw_refresh_token:str,
        access_token_jti:str,
        access_token_exp:datetime
    ) -> None:

        token_hash = hashlib.sha256(raw_refresh_token.encode()).hexdigest()
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.token_hash == token_hash,RefreshToken.revoked_at._is(None),)
            .values(revoked_at=func.now())
        )

        ttl = int((access_token_exp - datetime.now(timezone.utc)).total_seconds())
        if ttl > 0:
            await BlacklistTokenService.add(access_token_jti, ttl)

        await db.commit()
        logger.info("logout", extra={"jti": access_token_jti})


    @staticmethod
    async def logout_all(
        db: AsyncSession,
        user_id: str,
        access_token_jti: str,
        access_token_exp: datetime,
    ) -> None:

        await AuthService.revoke_all_sessions(db, user_id)

        ttl = int((access_token_exp - datetime.now(timezone.utc)).totalseconds())
        if ttl > 0:
            await BlacklistTokenService.add(access_token_jti, ttl)

        await db.commit()
        logger.info("logout_all", extra={"user_id": str(user_id), "jti": access_token_jti})

        
    @staticmethod
    async def _issue_token_pair(
        db: AsyncSession,
        user: User,
        tenant_id: str,
        family_id: str,
        device_info: dict,
    ) -> TokenResponse:
        roles = [ur.role.name for ur in user.roles] if user.roles else []
        jti = str(uuid4())
        access_token = create_access_token(
            subject=str(user.id),
            tenant_id=str(tenant_id),
            roles=roles,
            jti=jti,
        )

        raw_refresh = secrets.token_hex(32)
        token_hash = hashlib.sha256(raw_refresh.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        db.add(RefreshToken(
            user_id=user.id,
            tenant_id=tenant_id,
            token_hash=token_hash,
            family_id=family_id,
            device_info=device_info,
            expires_at=expires_at,
        ))

        return TokenResponse(access_token=access_token, refresh_token=raw_refresh)
    