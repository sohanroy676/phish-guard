from fastapi import APIRouter, Request

from phishguard.app.db import db_is_ok

router = APIRouter(prefix="/api")


@router.get("/health")
def health(request: Request) -> dict:
    scorers = {"url": request.app.state.url_scorer, "email": request.app.state.email_scorer}
    return {
        "status": "ok",
        "db": "ok" if db_is_ok(request.app.state.engine) else "error",
        "models": {k: v.version for k, v in scorers.items() if v},
    }
