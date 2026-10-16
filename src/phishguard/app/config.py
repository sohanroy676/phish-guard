from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from phishguard.core.registry import MODELS_DIR

_PLACEHOLDERS = {"", "change-me"}
MIN_SECRET_LEN = 16


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    secret_key: str = ""
    hmac_pepper: str = ""
    database_url: str = "sqlite:///./phishguard.db"
    retention_days: int = 30
    model_version_url: str = ""
    model_version_email: str = ""
    models_dir: Path = MODELS_DIR
    session_hours: int = 12
    cookie_secure: bool = False  # set COOKIE_SECURE=true when served over HTTPS


def check_secrets(settings: Settings) -> None:
    """Refuse to start with missing or placeholder secrets."""
    for name in ("secret_key", "hmac_pepper"):
        value = getattr(settings, name)
        if value in _PLACEHOLDERS or len(value) < MIN_SECRET_LEN:
            raise RuntimeError(
                f"{name.upper()} is missing or a placeholder. Set a real value in .env "
                f"(at least {MIN_SECRET_LEN} characters)."
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
