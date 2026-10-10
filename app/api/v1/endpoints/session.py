from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, func
from uuid import UUID

from app.core.database import get_db
from app.api.v1.deps import get_current_user, get_token_payload
from app.models import User, RefreshToken
from app.schemas import SessionResponse

router = APIRouter()


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    payload: dict = Depends(get_token_payload),
):
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == current_user.id,
            RefreshToken.revoked_at.is_(None),
        )
    )
    tokens = result.scalars().all()
    current_sid = payload.get("sid")
    return [
        SessionResponse(
            session_id=t.family_id,
            ip=t.device_info.get("ip") if t.device_info else None,
            device_info=t.device_info,
            last_seen=t.created_at,
            is_current=current_sid is not None and str(t.family_id) == str(current_sid),
        )
        for t in tokens
    ]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.family_id == session_id,
            RefreshToken.user_id == current_user.id,
            RefreshToken.revoked_at.is_(None),
        )
    )
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=404, detail="Session not found")

    await db.execute(
        update(RefreshToken)
        .where(
            RefreshToken.family_id == session_id,
            RefreshToken.user_id == current_user.id,
        )
        .values(revoked_at=func.now())
    )
    await db.commit()
