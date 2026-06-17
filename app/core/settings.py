from typing import Literal
from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    ENV:Literal["development", "production"] = "development"
    PROJECT_NAME: str = "authservice"

    DB_USER: str = "postgres"
    DB_PASSWORD: str = "postgres"
    DB_HOST: str = "db"
    DB_PORT: int = 5432
    DB_NAME: str = "auth_db"
    DB_URL: str | None = None

    @computed_field
    @property
    def DATABASE_URL(self) -> str:
        if self.DB_URL:
            return self.DB_URL
        return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    model_config = SettingsConfigDict(
        env_file= ".env",
        env_file_encoding = "utf-8",
        extra="ignore"
    )

settings = Settings()
print(settings)