from uuid import UUID
from pydantic import BaseModel, EmailStr, Field

class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str= Field(..., min_length=8)
    tenant_slug: str

class UserRegisterResponse(BaseModel):
    user_id: UUID
    message: str = "Verification email sent"

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_slug: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 15 * 60

class RefreshTokenRequest(BaseModel):
    refresh_token: str