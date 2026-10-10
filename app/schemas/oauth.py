from pydantic import BaseModel


class OAuthCallbackResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 900