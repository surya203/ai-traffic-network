import asyncio

from fastapi import APIRouter, Depends

from app.core.security import CurrentUser, get_current_user
from app.services.dashboard_stats import build_dashboard
from app.services.supabase_data import (
    ALERT_COLUMNS,
    EVENT_COLUMNS,
    JOB_COLUMNS,
    UPLOAD_COLUMNS,
    rest_select,
)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("")
async def read_dashboard(user: CurrentUser = Depends(get_current_user)) -> dict:
    uploads, jobs, events, alerts = await asyncio.gather(
        rest_select(user.token, "uploads", UPLOAD_COLUMNS, order="created_at.desc", limit=200),
        rest_select(user.token, "analysis_jobs", JOB_COLUMNS, order="created_at.desc", limit=200),
        rest_select(user.token, "network_events", EVENT_COLUMNS, order="first_seen.desc", limit=2000),
        rest_select(user.token, "alerts", ALERT_COLUMNS, order="detected_at.desc", limit=200),
    )
    stats = build_dashboard(uploads=uploads, jobs=jobs, events=events, alerts=alerts)
    stats["partial"] = len(uploads) == 200 or len(jobs) == 200 or len(events) == 2000 or len(alerts) == 200
    return stats
