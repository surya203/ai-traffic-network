import asyncio
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.core.security import CurrentUser, get_current_user
from app.services.assistant import assemble
from app.services.openai_chat import answer_question
from app.services.supabase_data import (
    ALERT_COLUMNS,
    JOB_COLUMNS,
    THREAT_COLUMNS,
    UPLOAD_COLUMNS,
    rest_select,
)

router = APIRouter(tags=["assistant"])

_EVENT_COLUMNS = "job_id,protocol,packet_count,source_ip,destination_ip,destination_port,evidence_type,details"


class Turn(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(max_length=4000)


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    history: list[Turn] = Field(default_factory=list, max_length=8)


@router.post("/assistant/chat")
async def chat(body: ChatIn, user: CurrentUser = Depends(get_current_user)) -> dict:
    uploads, jobs, alerts, threats, events = await asyncio.gather(
        rest_select(user.token, "uploads", UPLOAD_COLUMNS, order="created_at.desc", limit=200),
        rest_select(user.token, "analysis_jobs", JOB_COLUMNS, order="created_at.desc", limit=200),
        rest_select(user.token, "alerts", ALERT_COLUMNS, order="detected_at.desc", limit=200),
        rest_select(user.token, "threat_analyses", THREAT_COLUMNS, order="created_at.desc", limit=100),
        rest_select(user.token, "network_events", _EVENT_COLUMNS, order="created_at.desc", limit=500),
    )
    snapshot = assemble(
        uploads,
        jobs,
        alerts,
        threats,
        events,
        partial=len(uploads) == 200 or len(jobs) == 200 or len(alerts) == 200 or len(events) == 500,
    )
    history = [{"role": turn.role, "content": turn.content} for turn in body.history]
    return await answer_question(body.message, snapshot, history)
