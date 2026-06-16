from fastapi import FastAPI
from app.core.settings import settings 

app = FastAPI(title=settings.PROJECT_NAME)


@app.get("/health")
def health_check():
    return {
        "status" : "ok",
        "environment" : settings.ENV
        }


