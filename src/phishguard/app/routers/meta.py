from fastapi import APIRouter, Request

from phishguard.app.db import db_is_ok

router = APIRouter(prefix="/api")


@router.get("/health")
def health(request: Request) -> dict:
    return {
        "status": "ok",
        "db": "ok" if db_is_ok(request.app.state.engine) else "error",
        "models": {},
    }
