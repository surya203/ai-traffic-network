import ssl
from functools import lru_cache
from typing import Any
from uuid import UUID

import certifi
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from pydantic import BaseModel

from app.core.config import Settings, get_settings

_bearer = HTTPBearer(auto_error=False)


class CurrentUser(BaseModel):
    id: str
    email: str | None = None
    token: str


@lru_cache
def _jwks_client(jwks_url: str) -> PyJWKClient:
    context = ssl.create_default_context(cafile=certifi.where())
    return PyJWKClient(jwks_url, cache_keys=True, lifespan=600, ssl_context=context)


def decode_access_token(token: str, settings: Settings) -> dict[str, Any]:
    if not settings.supabase_url:
        raise HTTPException(status_code=503, detail="Supabase URL is not configured")

    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid session") from exc

    algorithm = header.get("alg")
    try:
        if algorithm == "HS256":
            if not settings.supabase_jwt_secret:
                raise HTTPException(status_code=503, detail="SUPABASE_JWT_SECRET is not configured")
            payload = jwt.decode(
                token,
                settings.supabase_jwt_secret,
                algorithms=["HS256"],
                audience="authenticated",
                issuer=settings.issuer,
            )
        elif algorithm in {"ES256", "RS256"}:
            signing_key = _jwks_client(settings.jwks_url).get_signing_key_from_jwt(token)
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=[algorithm],
                audience="authenticated",
                issuer=settings.issuer,
            )
        else:
            raise HTTPException(status_code=401, detail="Invalid session")
    except HTTPException:
        raise
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid session") from exc

    if payload.get("role") != "authenticated":
        raise HTTPException(status_code=401, detail="Invalid session")

    try:
        UUID(str(payload.get("sub")))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Invalid session") from exc

    return payload


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    settings: Settings = Depends(get_settings),
) -> CurrentUser:
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = decode_access_token(credentials.credentials, settings)
    return CurrentUser(
        id=str(payload["sub"]),
        email=payload.get("email"),
        token=credentials.credentials,
    )
