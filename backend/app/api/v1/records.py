from fastapi import APIRouter, Depends

from app.core.security import CurrentUser, get_current_user
from app.services.supabase_data import (
    ALERT_COLUMNS,
    GEO_COLUMNS,
    JOB_COLUMNS,
    REPORT_COLUMNS,
    THREAT_COLUMNS,
    rest_select,
)

router = APIRouter(tags=["records"])


@router.get("/analysis")
async def list_jobs(user: CurrentUser = Depends(get_current_user)) -> dict:
    rows = await rest_select(user.token, "analysis_jobs", JOB_COLUMNS, order="created_at.desc", limit=200)
    return {"jobs": rows}


@router.get("/alerts")
async def list_alerts(user: CurrentUser = Depends(get_current_user)) -> dict:
    rows = await rest_select(user.token, "alerts", ALERT_COLUMNS, order="detected_at.desc", limit=200)
    return {"alerts": rows}


@router.get("/threats")
async def list_threats(user: CurrentUser = Depends(get_current_user)) -> dict:
    rows = await rest_select(user.token, "threat_analyses", THREAT_COLUMNS, order="created_at.desc", limit=100)
    return {"threats": rows}


@router.get("/reports")
async def list_reports(user: CurrentUser = Depends(get_current_user)) -> dict:
    rows = await rest_select(user.token, "reports", REPORT_COLUMNS, order="created_at.desc", limit=100)
    return {"reports": rows}


@router.get("/geolocation")
async def list_geolocation(user: CurrentUser = Depends(get_current_user)) -> dict:
    rows = await rest_select(
        user.token,
        "ip_geolocations",
        GEO_COLUMNS,
        order="looked_up_at.desc",
        limit=500,
    )
    return {"locations": rows}
