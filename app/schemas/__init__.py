from app.schemas.admin import AdminCreateUserRequest, AdminAssignRolesRequest, AdminUserResponse
from app.schemas.auth import (
    LoginRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserRegisterRequest,
    UserRegisterResponse,
)
from app.schemas.identity import (
    EmailVerifyRequest,
    MessageResponse,
    PasswordChangeRequest,
    PasswordResetConfirmBody,
    PasswordResetRequestBody,
)
from app.schemas.oauth import OAuthCallbackResponse
from app.schemas.session import SessionResponse

from pydantic import BaseModel

__all__ = [
    "UserRegisterRequest",
    "UserRegisterResponse",
    "LoginRequest",
    "TokenResponse",
    "RefreshTokenRequest",
    "EmailVerifyRequest",
    "PasswordResetRequestBody",
    "PasswordResetConfirmBody",
    "PasswordChangeRequest",
    "MessageResponse",
    "SessionResponse",
    "OAuthCallbackResponse",
    "AdminCreateUserRequest",
    "AdminAssignRolesRequest",
    "AdminUserResponse",
]
