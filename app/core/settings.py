from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    ENV:Literal["development", "production"] = "development"
    PROJECT_NAME: str = "authservice"

    model_config = SettingsConfigDict(
        env_file= ".env",
        env_file_encoding = "utf-8",
        extra="ignore"
    )

settings = Settings()
print(settings)