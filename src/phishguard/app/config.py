from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    secret_key: str = ""
    hmac_pepper: str = ""
    database_url: str = "sqlite:///./phishguard.db"
    retention_days: int = 30
    model_version_url: str = ""
    model_version_email: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
