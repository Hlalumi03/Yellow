from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "Yellow Store"
    environment: str = "development"
    database_url: str = f"sqlite:///{(PROJECT_ROOT / 'yellow_store.sqlite3').as_posix()}"
    session_cookie_name: str = "auth_session"
    session_lifetime_seconds: int = 60 * 60 * 24 * 7
    secure_cookies: bool = False
    allowed_origins: list[str] = []


@lru_cache
def get_settings() -> Settings:
    return Settings()
