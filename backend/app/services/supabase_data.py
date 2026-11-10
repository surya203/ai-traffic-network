import logging

import httpx
from fastapi import HTTPException

from app.core.config import get_settings

logger = logging.getLogger(__name__)

UPLOAD_COLUMNS = "id,filename,file_kind,size_bytes,status,sha256,storage_path,created_at"
JOB_COLUMNS = "id,upload_id,status,progress,error_message,created_at"
EVENT_COLUMNS = "job_id,protocol,packet_count,source_ip,destination_ip,first_seen,evidence_type"
ALERT_COLUMNS = "id,job_id,title,severity,category,source_ip,destination_ip,status,detected_at,explanation"
THREAT_COLUMNS = "id,job_id,model,prompt_version,findings,created_at"
REPORT_COLUMNS = "id,job_id,status,storage_path,created_at"
GEO_COLUMNS = "ip,country,country_code,city,latitude,longitude,source,looked_up_at"


def _headers(token: str) -> dict[str, str]:
    settings = get_settings()
    api_key = settings.secret_key if token and token == settings.secret_key else settings.publishable_key
    return {
        "apikey": api_key,
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


def _base_url() -> str:
    settings = get_settings()
    if not settings.supabase_url or not settings.publishable_key:
        raise HTTPException(status_code=503, detail="Supabase URL and publishable key are not configured")
    return settings.supabase_url.rstrip("/") + "/rest/v1/"


async def rest_select(
    token: str,
    table: str,
    columns: str,
    *,
    order: str,
    limit: int,
    filters: dict | None = None,
) -> list[dict]:
    params = {"select": columns, "order": order, "limit": str(limit)}
    for key, value in (filters or {}).items():
        params[key] = f"eq.{value}"
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(_base_url() + table, headers=_headers(token), params=params)
    return _rows(response)


async def rest_insert(token: str, table: str, row: dict) -> dict:
    headers = _headers(token)
    headers["Content-Type"] = "application/json"
    headers["Prefer"] = "return=representation"
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(_base_url() + table, headers=headers, json=row)
    rows = _rows(response)
    if not rows:
        raise HTTPException(status_code=403, detail="Supabase did not save that row")
    return rows[0]


async def rest_delete(token: str, table: str, row_id: str) -> None:
    headers = _headers(token)
    headers["Prefer"] = "return=representation"
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.delete(
            _base_url() + table,
            headers=headers,
            params={"id": f"eq.{row_id}"},
        )
    rows = _rows(response)
    if not rows:
        raise HTTPException(status_code=404, detail="Record not found")


async def rest_update(token: str, table: str, row: dict, filters: dict) -> list[dict]:
    params = {key: f"eq.{value}" for key, value in filters.items()}
    headers = _headers(token)
    headers["Content-Type"] = "application/json"
    headers["Prefer"] = "return=representation"
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.patch(_base_url() + table, headers=headers, params=params, json=row)
    return _rows(response)


async def rest_insert_many(token: str, table: str, rows: list[dict]) -> None:
    if not rows:
        return
    headers = _headers(token)
    headers["Content-Type"] = "application/json"
    headers["Prefer"] = "return=minimal"
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(_base_url() + table, headers=headers, json=rows)
    if response.status_code == 401:
        raise HTTPException(status_code=401, detail="Supabase rejected the session")
    if response.status_code >= 400:
        logger.warning("Supabase insert failed status=%s table=%s", response.status_code, table)
        raise HTTPException(status_code=502, detail="Supabase query failed")


def _rows(response: httpx.Response) -> list[dict]:
    if response.status_code == 401:
        raise HTTPException(status_code=401, detail="Supabase rejected the session")
    if response.status_code >= 400:
        logger.warning("Supabase query failed status=%s", response.status_code)
        raise HTTPException(status_code=502, detail="Supabase query failed")
    if not response.content:
        return []
    data = response.json()
    if not isinstance(data, list):
        raise HTTPException(status_code=502, detail="Unexpected Supabase response")
    return data
