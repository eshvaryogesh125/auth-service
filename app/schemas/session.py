from datetime import datetime
from typing import Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict


class SessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: UUID
    ip: str | None = None
    device_info: dict[str, Any] | None = None
    last_seen: datetime
    is_current: bool = False