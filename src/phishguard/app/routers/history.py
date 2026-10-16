from datetime import UTC
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from phishguard.app import auth
from phishguard.app.models_db import Analysis, SessionRow

router = APIRouter(prefix="/api/history")

MAX_LIMIT = 200


def serialize(a: Analysis) -> dict:
    """An allow-list: input_hmac and latency never leave the server."""
    created = a.created_at if a.created_at.tzinfo else a.created_at.replace(tzinfo=UTC)
    return {
        "id": a.id,
        "created_at": created.isoformat(),
        "kind": a.kind,
        "display_host": a.display_host,
        "band": a.band,
        "model_reasons": a.model_reasons,
        "rule_warnings": a.rule_warnings,
        "model_version": a.model_version,
    }


@router.get("")
def list_history(
    kind: Literal["url", "email"] | None = None,
    band: Literal["high", "suspicious", "low", "cant_assess"] | None = None,
    limit: int = Query(50, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
    row: SessionRow = Depends(auth.current_session),
    db: Session = Depends(auth.get_db),
) -> dict:
    query = select(Analysis).where(Analysis.user_id == row.user_id)
    if kind:
        query = query.where(Analysis.kind == kind)
    if band:
        query = query.where(Analysis.band == band)
    query = query.order_by(Analysis.created_at.desc(), Analysis.id.desc())
    items = db.scalars(query.limit(limit).offset(offset)).all()
    return {"items": [serialize(a) for a in items], "limit": limit, "offset": offset}


@router.delete("")
def delete_history(
    row: SessionRow = Depends(auth.csrf_protected),
    db: Session = Depends(auth.get_db),
) -> dict:
    result = db.execute(delete(Analysis).where(Analysis.user_id == row.user_id))
    db.commit()
    return {"deleted": result.rowcount}
