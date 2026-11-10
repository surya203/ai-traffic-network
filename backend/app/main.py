import logging

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import analysis, assistant, auth, dashboard, records, uploads
from app.core.config import get_settings

logger = logging.getLogger("sentinel")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="AI Network Sentinel", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(dashboard.router, prefix="/api/v1")
    app.include_router(uploads.router, prefix="/api/v1")
    app.include_router(records.router, prefix="/api/v1")
    app.include_router(analysis.router, prefix="/api/v1")
    app.include_router(assistant.router, prefix="/api/v1")

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):  # noqa: ANN001
        logger.info("invalid request on %s", request.url.path)
        return JSONResponse(status_code=422, content={"detail": "Check the submitted fields"})

    @app.exception_handler(Exception)
    async def unhandled(request, exc):  # noqa: ANN001
        if isinstance(exc, HTTPException):
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        logger.exception("unhandled error on %s", request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Something went wrong"})

    return app


app = create_app()
