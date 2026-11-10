from fastapi import APIRouter, BackgroundTasks, Depends

from app.core.security import CurrentUser, get_current_user
from app.services.job_runner import execute_job
from app.services.supabase_data import UPLOAD_COLUMNS, rest_select, rest_update

router = APIRouter(tags=["analysis"])


@router.post("/analysis/run-queued")
async def run_queued(background: BackgroundTasks, user: CurrentUser = Depends(get_current_user)) -> dict:
    jobs = await rest_select(
        user.token,
        "analysis_jobs",
        "id,upload_id,user_id,status,progress",
        order="created_at.asc",
        limit=20,
        filters={"status": "queued"},
    )
    uploads = await rest_select(user.token, "uploads", UPLOAD_COLUMNS, order="created_at.desc", limit=200)
    by_id = {row["id"]: row for row in uploads}
    started = []
    for job in jobs:
        upload = by_id.get(job.get("upload_id"))
        if upload is None:
            continue
        claimed = await rest_update(
            user.token,
            "analysis_jobs",
            {"status": "processing", "progress": 5, "error_message": None},
            {"id": job["id"], "status": "queued"},
        )
        if not claimed:
            continue
        started.append(job["id"])
        background.add_task(execute_job, user.token, job, upload)
    return {"started": started}
