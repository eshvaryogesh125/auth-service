from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class AdminCreateUserRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    tenant_slug: str
    roles: list[str] = ["member"]


class AdminAssignRolesRequest(BaseModel):
    roles: list[str] = Field(..., min_length=1)


class AdminUserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: UUID
    email: EmailStr
    is_active: bool
    is_verified: bool
    roles: list[str] = []
    created_at: datetime
    updated_at: datetime