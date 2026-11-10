from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.security import CurrentUser, get_current_user
from app.services.supabase_data import UPLOAD_COLUMNS, rest_delete, rest_insert, rest_select
from app.services.uploads import PathRejected, owned_storage_path

router = APIRouter(prefix="/uploads", tags=["uploads"])


class UploadComplete(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    storage_path: str = Field(min_length=1, max_length=500)
    file_kind: str = Field(pattern=r"^(pcap|pcapng|json|pdf)$")
    size_bytes: int = Field(ge=0, le=52_428_800)
    sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    content_type: str | None = Field(default=None, max_length=200)


def _uuid(value: str) -> str:
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Upload not found") from exc


@router.get("")
async def list_uploads(user: CurrentUser = Depends(get_current_user)) -> dict:
    rows = await rest_select(user.token, "uploads", UPLOAD_COLUMNS, order="created_at.desc", limit=200)
    return {"uploads": rows}


@router.post("/complete")
async def complete_upload(body: UploadComplete, user: CurrentUser = Depends(get_current_user)) -> dict:
    try:
        path = owned_storage_path(user.id, body.storage_path)
    except PathRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    upload = await rest_insert(
        user.token,
        "uploads",
        {
            "user_id": user.id,
            "filename": body.filename.strip(),
            "storage_path": path,
            "bucket": "network-uploads",
            "content_type": body.content_type,
            "file_kind": body.file_kind,
            "size_bytes": body.size_bytes,
            "sha256": body.sha256.lower(),
            "status": "uploaded",
        },
    )
    try:
        job = await rest_insert(
            user.token,
            "analysis_jobs",
            {
                "user_id": user.id,
                "upload_id": upload["id"],
                "status": "queued",
                "progress": 0,
            },
        )
    except HTTPException:
        await rest_delete(user.token, "uploads", upload["id"])
        raise
    return {"upload": upload, "job": job}


@router.delete("/{upload_id}")
async def delete_upload(upload_id: str, user: CurrentUser = Depends(get_current_user)) -> dict:
    await rest_delete(user.token, "uploads", _uuid(upload_id))
    return {"deleted": True}
