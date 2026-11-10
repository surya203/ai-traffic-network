import logging
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from app.core.config import get_settings
from app.services.openai_chat import complete_chat, reviewer_messages
from app.services.supabase_data import rest_insert, rest_insert_many, rest_update
from app.services.traffic import analyze_flows, parse_json_bytes, parse_pcap_bytes, parse_pdf_bytes

logger = logging.getLogger(__name__)

_ALERT_CATEGORIES = {
    "possible_port_scanning",
    "repeated_connection_attempts",
    "possible_high_volume",
    "possible_dns_anomaly",
    "document_only",
}


async def execute_job(token: str, job: dict, upload: dict) -> None:
    job_id = job["id"]
    user_id = job["user_id"]
    try:
        await _progress(token, job_id, 15)
        payload = await _download(token, upload["storage_path"])
        await _progress(token, job_id, 45)
        flows = _parse(upload.get("file_kind"), payload)
        findings = analyze_flows(flows)
        note = await _reviewer_note(upload, findings, flows)
        if note:
            findings = {**findings, "analyst_note": note}
        await _progress(token, job_id, 75)
        await _store_flows(token, job_id, user_id, flows)
        analysis = await rest_insert(
            token,
            "threat_analyses",
            {
                "user_id": user_id,
                "job_id": job_id,
                "model": get_settings().openai_model if note else "rules-v1",
                "prompt_version": "rules-2026-11-10+openai" if note else "rules-2026-11-10",
                "findings": findings,
            },
        )
        await _store_alerts(token, job_id, user_id, analysis["id"], findings["findings"])
        await rest_update(
            token,
            "analysis_jobs",
            {
                "status": "completed",
                "progress": 100,
                "finished_at": _now(),
                "error_message": None,
            },
            {"id": job_id},
        )
    except Exception as exc:
        logger.exception("analysis failed for job %s", job_id)
        await rest_update(
            token,
            "analysis_jobs",
            {
                "status": "failed",
                "progress": 100,
                "finished_at": _now(),
                "error_message": str(exc)[:300] or "Analysis failed",
            },
            {"id": job_id},
        )


def _parse(kind: str | None, payload: bytes) -> list[dict]:
    if kind in {"pcap", "pcapng"}:
        return parse_pcap_bytes(payload)
    if kind == "json":
        return parse_json_bytes(payload)
    if kind == "pdf":
        return parse_pdf_bytes(payload)
    raise ValueError("This file type cannot be analyzed")


async def _download(token: str, storage_path: str) -> bytes:
    settings = get_settings()
    api_key = settings.secret_key if token and token == settings.secret_key else settings.publishable_key
    encoded = quote(storage_path, safe="/")
    url = f"{settings.supabase_url.rstrip('/')}/storage/v1/object/network-uploads/{encoded}"
    headers = {"apikey": api_key, "Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(url, headers=headers)
    if response.status_code >= 400:
        raise ValueError("The stored file could not be downloaded")
    return response.content


async def _store_flows(token: str, job_id: str, user_id: str, flows: list[dict]) -> None:
    rows = []
    for flow in flows:
        rows.append(
            {
                "job_id": job_id,
                "user_id": user_id,
                "source_ip": flow.get("source_ip"),
                "destination_ip": flow.get("destination_ip"),
                "source_port": flow.get("source_port"),
                "destination_port": flow.get("destination_port"),
                "protocol": flow.get("protocol"),
                "packet_count": flow.get("packet_count") or 0,
                "byte_count": flow.get("byte_count") or 0,
                "first_seen": flow.get("first_seen"),
                "last_seen": flow.get("last_seen"),
                "tcp_flags": flow.get("tcp_flags") or [],
                "dns_query": flow.get("dns_query"),
                "evidence_type": flow.get("evidence_type") or "aggregated",
                "details": flow.get("details") or {},
            }
        )
    for start in range(0, len(rows), 200):
        await rest_insert_many(token, "network_events", rows[start : start + 200])


async def _reviewer_note(upload: dict, findings: dict, flows: list[dict]) -> str:
    if not get_settings().openai_api_key.strip():
        return ""
    from app.services.assistant import assemble

    upload_id = upload.get("id") or "current"
    events = []
    for flow in flows[:20]:
        events.append({**flow, "job_id": "current"})
    snapshot = assemble(
        [{"id": upload_id, "filename": upload.get("filename"), "file_kind": upload.get("file_kind"), "size_bytes": upload.get("size_bytes")}],
        [{"id": "current", "upload_id": upload_id, "status": "processing", "progress": 75}],
        [],
        [{"job_id": "current", "findings": findings}],
        events,
    )
    try:
        return await complete_chat(reviewer_messages(snapshot), max_tokens=300)
    except Exception:
        logger.warning("OpenAI reviewer note skipped")
        return ""


async def _store_alerts(token: str, job_id: str, user_id: str, analysis_id: str, findings: list[dict]) -> None:
    rows = []
    for finding in findings:
        if finding.get("category") not in _ALERT_CATEGORIES:
            continue
        rows.append(
            {
                "job_id": job_id,
                "user_id": user_id,
                "analysis_id": analysis_id,
                "title": finding.get("title") or "Review finding",
                "severity": finding.get("severity") or "low",
                "category": finding.get("category"),
                "source_ip": finding.get("source_ip"),
                "destination_ip": finding.get("destination_ip"),
                "explanation": finding.get("explanation"),
                "evidence": finding.get("evidence") or [],
                "recommendations": finding.get("recommendations") or [],
                "status": "open",
                "detected_at": _now(),
            }
        )
    await rest_insert_many(token, "alerts", rows)


async def _progress(token: str, job_id: str, progress: int) -> None:
    await rest_update(token, "analysis_jobs", {"progress": progress}, {"id": job_id})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
