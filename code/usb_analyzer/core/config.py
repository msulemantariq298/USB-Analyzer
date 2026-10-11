from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from USB_ANALYZER_* environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="USB_ANALYZER_",
        env_file=".env",
        extra="ignore",
    )

    app_name: str = "USB Analyzer"
    database_path: Path = Field(default=Path("data/usb_analyzer.db"))
    api_prefix: str = "/api/v1"
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
