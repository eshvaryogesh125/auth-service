from fastapi import FastAPI

from app.core.settings import settings 
from app.core.logging import logger
from app.api.v1.router import api_router

app = FastAPI(
        title=settings.PROJECT_NAME,
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )

app.include_router(api_router)

@app.get("/health")
def health_check():
    logger.info("helloooo")
    return {
        "status" : "ok",
        "environment" : settings.ENV
    }


