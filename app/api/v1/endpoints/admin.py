from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID

from app.core.database import get_db
from app.api.v1.deps import require_role
from app.models import User, RefreshToken
from app.schemas import (
    AdminCreateUserRequest,
    AdminAssignRolesRequest,
)
from app.services.user_services import UserService
from app.services.auth_services import AuthService

router = APIRouter(dependencies=[Depends(require_role("admin"))])


@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    body: AdminCreateUserRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        user = await UserService.register(
            db=db,
            email=body.email,
            password=body.password,
            tenant_slug=body.tenant_slug,
        )
        return {"user_id": str(user.id)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/users/{user_id}/deactivate", status_code=status.HTTP_200_OK)
async def deactivate_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = False
    await db.commit()
    return {"message": "User deactivated"}


@router.post("/users/{user_id}/reactivate", status_code=status.HTTP_200_OK)
async def reactivate_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = True
    await db.commit()
    return {"message": "User reactivated"}


@router.post("/users/{user_id}/force-password-reset", status_code=status.HTTP_200_OK)
async def force_password_reset(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await AuthService.revoke_all_sessions(db=db, user_id=str(user_id))
    await db.commit()
    return {"message": "Sessions revoked, password reset required"}


@router.get("/users/{user_id}/sessions")
async def get_user_sessions(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked_at.is_(None),
        )
    )
    tokens = result.scalars().all()
    return [{"session_id": str(t.id), "device_info": t.device_info, "created_at": t.created_at} for t in tokens]


@router.put("/users/{user_id}/roles", status_code=status.HTTP_200_OK)
async def assign_roles(
    user_id: UUID,
    body: AdminAssignRolesRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        await UserService.assign_roles(db=db, user_id=user_id, role_names=body.roles)
        return {"message": "Roles updated"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))