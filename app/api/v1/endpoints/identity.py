from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.api.v1.deps import get_current_user, rate_limit
from app.core.exceptions import (
    AuthError,
    InvalidCurrentPasswordError,
    InvalidOrExpiredTokenError,
    TenantNotFoundError,
    UserNotFoundError,
)
from app.core.logging import logger
from app.models import User
from app.schemas import (
    EmailVerifyRequest,
    PasswordResetRequestBody,
    PasswordResetConfirmBody,
    PasswordChangeRequest,
)
from app.services.email_services import get_email_service
from app.services.user_services import UserService

router = APIRouter()


@router.post("/email/verify",status_code=status.HTTP_200_OK)
async def verify_email(
    body: EmailVerifyRequest,
    db: AsyncSession = Depends(get_db)
):

    try:
        await UserService.verify_email(db=db, token=body.token)
        return {"message": "Email verified"}
    except InvalidOrExpiredTokenError as exc:
        raise HTTPException(status_code=400, detail="Invalid or expired token") from exc
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/password-reset/request",status_code=status.HTTP_200_OK)
async def password_reset_request(
    body: PasswordResetRequestBody,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(rate_limit(3, 60 * 60, "pwreset"))
):

    try:
        email_service = get_email_service()
        await UserService.request_password_reset(
            db=db,
            email_service=email_service,
            email=body.email,
            tenant_slug=body.tenant_slug,
        )
    except Exception:
        logger.exception("password_reset_request_failed")

    return {"message": "Reset email sent"}

@router.post("/password-reset/confirm", status_code=status.HTTP_200_OK)
async def password_reset_confirm(
    body: PasswordResetConfirmBody,
    db: AsyncSession = Depends(get_db)
):

    try:
        await UserService.confirm_password_request(
            db=db, token=body.token, new_password=body.new_password
        )
        return {"message": "Password updated"}
    except InvalidOrExpiredTokenError as exc:
        raise HTTPException(status_code=400, detail="Invalid or expired token") from exc
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/password/change", status_code=status.HTTP_200_OK)
async def change_password(
    body: PasswordChangeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    try:
        await UserService.change_password(
            db=db,
            user=current_user,
            current_password=body.current_password,
            new_password=body.new_password
        )
        return {"message": "Password changed"}
    except InvalidCurrentPasswordError as exc:
        raise HTTPException(status_code=401, detail="Wrong current password") from exc
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc