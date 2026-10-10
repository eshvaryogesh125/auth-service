from pydantic import BaseModel, EmailStr, Field


class EmailVerifyRequest(BaseModel):
    token: str


class PasswordResetRequestBody(BaseModel):
    email: EmailStr
    tenant_slug: str


class PasswordResetConfirmBody(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


class MessageResponse(BaseModel):
    message: str