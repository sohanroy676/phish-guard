"""Retention purge. Rows strictly older than the retention window are deleted."""

import asyncio
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session, sessionmaker

from phishguard.app.models_db import Analysis, SessionRow

log = logging.getLogger("phishguard.retention")

PURGE_INTERVAL_SECONDS = 24 * 60 * 60


def purge_old(
    factory: sessionmaker[Session], retention_days: int, now: datetime | None = None
) -> int:
    """Delete old analyses and expired sessions; returns the analysis count."""
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=retention_days)
    with factory() as db:
        result = db.execute(delete(Analysis).where(Analysis.created_at < cutoff))
        db.execute(delete(SessionRow).where(SessionRow.expires_at < now))
        db.commit()
        return result.rowcount


async def purge_daily(factory: sessionmaker[Session], retention_days: int) -> None:
    while True:
        await asyncio.sleep(PURGE_INTERVAL_SECONDS)
        try:
            deleted = await asyncio.to_thread(purge_old, factory, retention_days)
            log.info("retention purge removed %d analyses", deleted)
        except Exception:
            log.exception("retention purge failed")
