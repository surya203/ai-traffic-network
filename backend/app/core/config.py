from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_DIR = Path(__file__).resolve().parents[2]
_REPO_DIR = _BACKEND_DIR.parent


class Settings(BaseSettings):
    supabase_url: str = ""
    supabase_publishable_key: str = ""
    supabase_anon_key: str = ""
    supabase_secret_key: str = ""
    supabase_service_role_key: str = ""
    supabase_jwt_secret: str = ""
    supabase_jwks_url: str = ""
    allowed_origins: str = "http://localhost:5173"
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"

    model_config = SettingsConfigDict(
        env_file=(str(_REPO_DIR / ".env"), str(_BACKEND_DIR / ".env")),
        extra="ignore",
    )

    @property
    def publishable_key(self) -> str:
        return self.supabase_publishable_key or self.supabase_anon_key

    @property
    def secret_key(self) -> str:
        return self.supabase_secret_key or self.supabase_service_role_key

    @property
    def issuer(self) -> str:
        return self.supabase_url.rstrip("/") + "/auth/v1"

    @property
    def jwks_url(self) -> str:
        if self.supabase_jwks_url.strip():
            return self.supabase_jwks_url.strip()
        return self.issuer + "/.well-known/jwks.json"

    @property
    def origins(self) -> list[str]:
        return [item.strip() for item in self.allowed_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
