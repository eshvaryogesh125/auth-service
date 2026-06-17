from fastapi import FastAPI
from app.core.settings import settings 

app = FastAPI(
        title=settings.PROJECT_NAME,
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )


@app.get("/health")
def health_check():
    return {
        "status" : "ok",
        "environment" : settings.ENV
    }


