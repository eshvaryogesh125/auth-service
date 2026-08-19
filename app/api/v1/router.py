from fastapi import APIRouter

from app.api.v1.endpoints import (
    admin, auth, identity, oauth, session
)

api_router = APIRouter(prefix="/api/v1/auth")

api_router.include_router(auth.router, tags=["Authentication"])
api_router.include_router(identity.router, tags=["Identity & Password"])
api_router.include_router(session.router, tags=["Session Management"])
api_router.include_router(oauth.router, prefix="/oauth", tags=["OAuth"])
api_router.include_router(admin.router, prefix="/admin", tags=["Admin"])
