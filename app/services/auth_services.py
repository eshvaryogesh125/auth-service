from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func

from app.models.token import RefreshToken
from app.core.logging import logger

class AuthService:

    @staticmethod
    async def revoke_all_session(db:AsyncSession, user_id: str) -> None:

        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=func.now())
        )
        await db.commit()
        logger.info("all_sessions_revoked", extra={"user_id": str(user_id)})