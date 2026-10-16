from dataclasses import asdict
from time import perf_counter

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from phishguard.app import auth, security
from phishguard.app.models_db import Analysis, SessionRow
from phishguard.core.explain import lr_reasons
from phishguard.core.risk import HIGH, SUSPICIOUS, assess
from phishguard.core.url.normalize import UnsupportedURL, normalize_url
from phishguard.core.url.rules import run_rules

router = APIRouter(prefix="/api/analyze")


class UrlRequest(BaseModel):
    url: str = Field(max_length=10_000)  # normalize_url gives the friendly length message


@router.post("/url")
def analyze_url(
    body: UrlRequest,
    request: Request,
    row: SessionRow = Depends(auth.csrf_protected),
    db: Session = Depends(auth.get_db),
) -> dict:
    scorer = request.app.state.url_scorer
    if scorer is None:
        raise HTTPException(status_code=503, detail="The URL model is not loaded.")
    started = perf_counter()
    try:
        url = normalize_url(body.url)
    except UnsupportedURL as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None

    hits = run_rules(url)
    risk = assess(scorer.score(url), scorer.t_high, scorer.t_low, hits)
    # Reasons explain a warning, so they are only shown for the two warning bands.
    reasons = lr_reasons(scorer.model, scorer.text(url)) if risk.band in (HIGH, SUSPICIOUS) else []
    warnings = [asdict(h) for h in hits]
    display_host = security.defang_host(url)

    db.add(
        Analysis(
            user_id=row.user_id,
            input_hmac=security.input_hmac(request.app.state.settings.hmac_pepper, url),
            display_host=display_host,
            band=risk.band,
            model_reasons=reasons,
            rule_warnings=warnings,
            model_version=scorer.version,
            latency_ms=round((perf_counter() - started) * 1000),
        )
    )
    db.commit()
    request.app.state.events.publish(row.user_id)
    return {
        "band": risk.band,
        "headline": risk.headline,
        "advice": risk.advice,
        "footer": risk.footer,
        "display_host": display_host,
        "model_reasons": reasons,
        "rule_warnings": warnings,
    }
