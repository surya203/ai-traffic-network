import base64
import time
from uuid import uuid4

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.security import decode_access_token
from app.main import app
from app.services.dashboard_stats import build_dashboard
from app.services.uploads import PathRejected, owned_storage_path

SECRET = "test-secret-with-enough-length-32b"
URL = "https://example.supabase.co"
USER_ID = "11111111-1111-4111-8111-111111111111"


def _settings() -> Settings:
    return Settings(
        supabase_url=URL,
        supabase_anon_key="anon",
        supabase_jwt_secret=SECRET,
        supabase_service_role_key="",
        allowed_origins="http://localhost:5173",
    )


def _token(**extra) -> str:
    payload = {
        "sub": USER_ID,
        "role": "authenticated",
        "aud": "authenticated",
        "iss": f"{URL}/auth/v1",
        "exp": int(time.time()) + 60,
        "email": "admin@example.com",
    }
    payload.update(extra)
    return jwt.encode(payload, SECRET, algorithm="HS256")


def test_health_is_public_and_data_routes_require_a_session():
    client = TestClient(app)
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/dashboard").status_code == 401
    assert client.get("/api/v1/uploads").status_code == 401


def test_dashboard_is_empty_without_rows():
    stats = build_dashboard(uploads=[], jobs=[], events=[], alerts=[])
    assert stats["uploads_total"] == 0
    assert stats["packets_total"] == 0
    assert stats["threats_total"] == 0
    assert stats["severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert stats["recent_investigations"] == []


def test_dashboard_counts_real_rows_only():
    upload_id = str(uuid4())
    stats = build_dashboard(
        uploads=[{"id": upload_id, "filename": "lab.pcap"}],
        jobs=[{"id": "job-1", "upload_id": upload_id, "status": "completed", "progress": 100, "created_at": "2026-11-10T00:00:00Z"}],
        events=[
            {
                "protocol": "TCP",
                "packet_count": 12,
                "source_ip": "203.0.113.10",
                "destination_ip": "198.51.100.8",
                "first_seen": "2026-11-10T01:00:00Z",
                "evidence_type": "aggregated",
            },
            {
                "protocol": "TCP",
                "packet_count": 4,
                "source_ip": "203.0.113.10",
                "destination_ip": "198.51.100.9",
                "first_seen": "2026-11-10T02:00:00Z",
                "evidence_type": "document",
            },
        ],
        alerts=[{"id": "a1", "title": "Review", "severity": "high", "category": "scan", "status": "open", "detected_at": "2026-11-10T03:00:00Z"}],
    )
    assert stats["uploads_total"] == 1
    assert stats["analyses_completed"] == 1
    assert stats["packets_total"] == 16
    assert stats["connections_total"] == 1
    assert stats["threats_total"] == 1
    assert stats["severity"]["high"] == 1
    assert stats["recent_investigations"][0]["filename"] == "lab.pcap"
    assert stats["top_source_ips"][0] == {"ip": "203.0.113.10", "count": 2}
    assert stats["timeline"] == [{"date": "2026-11-10", "packets": 16}]


def test_hs256_session_returns_user():
    payload = decode_access_token(_token(), _settings())
    assert payload["sub"] == USER_ID
    assert payload["email"] == "admin@example.com"


def test_anon_role_is_rejected():
    with pytest.raises(HTTPException) as raised:
        decode_access_token(_token(role="anon"), _settings())
    assert raised.value.status_code == 401


def test_expired_token_is_rejected():
    with pytest.raises(HTTPException) as raised:
        decode_access_token(_token(exp=int(time.time()) - 10), _settings())
    assert raised.value.status_code == 401


def test_unsupported_algorithm_is_rejected():
    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        b'{"sub":"11111111-1111-4111-8111-111111111111","role":"authenticated"}'
    ).rstrip(b"=").decode()
    with pytest.raises(HTTPException) as raised:
        decode_access_token(f"{header}.{body}.", _settings())
    assert raised.value.status_code == 401


def test_storage_path_must_stay_in_the_user_folder():
    assert owned_storage_path(USER_ID, f"{USER_ID}/capture.pcap") == f"{USER_ID}/capture.pcap"
    with pytest.raises(PathRejected):
        owned_storage_path(USER_ID, "other-user/capture.pcap")
    with pytest.raises(PathRejected):
        owned_storage_path(USER_ID, f"{USER_ID}/../capture.pcap")
