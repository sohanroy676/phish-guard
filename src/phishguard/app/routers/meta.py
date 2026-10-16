from fastapi import APIRouter, Request

from phishguard.app.db import db_is_ok

router = APIRouter(prefix="/api")


@router.get("/health")
def health(request: Request) -> dict:
    scorer = request.app.state.url_scorer
    return {
        "status": "ok",
        "db": "ok" if db_is_ok(request.app.state.engine) else "error",
        "models": {"url": scorer.version} if scorer else {},
    }
