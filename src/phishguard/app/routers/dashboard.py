from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from phishguard.app import auth
from phishguard.app.models_db import Analysis, SessionRow
from phishguard.app.routers.history import serialize
from phishguard.core.risk import CANT_ASSESS, HIGH, LOW, SUSPICIOUS

router = APIRouter(prefix="/api/dashboard")

TREND_DAYS = 30
RECENT_HIGH = 5
BANDS = (HIGH, SUSPICIOUS, LOW, CANT_ASSESS)
KINDS = ("url", "email")


@router.get("/summary")
def summary(
    row: SessionRow = Depends(auth.current_session),
    db: Session = Depends(auth.get_db),
) -> dict:
    mine = Analysis.user_id == row.user_id

    by_band = dict.fromkeys(BANDS, 0)
    by_band.update(
        db.execute(select(Analysis.band, func.count()).where(mine).group_by(Analysis.band)).all()
    )
    by_kind = dict.fromkeys(KINDS, 0)
    by_kind.update(
        db.execute(select(Analysis.kind, func.count()).where(mine).group_by(Analysis.kind)).all()
    )

    today = datetime.now(UTC).date()
    first = today - timedelta(days=TREND_DAYS - 1)
    day = func.date(Analysis.created_at)
    counts = dict(
        db.execute(
            select(day, func.count()).where(mine, day >= first.isoformat()).group_by(day)
        ).all()
    )
    trend = [
        {"date": d.isoformat(), "count": counts.get(d.isoformat(), 0)}
        for d in (first + timedelta(days=i) for i in range(TREND_DAYS))
    ]

    recent = db.scalars(
        select(Analysis)
        .where(mine, Analysis.band.in_((HIGH, SUSPICIOUS)))
        .order_by(Analysis.created_at.desc(), Analysis.id.desc())
        .limit(RECENT_HIGH)
    ).all()
    return {
        "total": sum(by_band.values()),
        "by_band": by_band,
        "by_kind": by_kind,
        "trend": trend,
        "recent_high_risk": [serialize(a) for a in recent],
    }
