from dataclasses import asdict
from time import perf_counter
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from phishguard.app import auth, security
from phishguard.app.models_db import Analysis, SessionRow
from phishguard.core.email.features import anchor_mismatches
from phishguard.core.email.parse import (
    EmailTooLarge,
    NotAnEmail,
    ParsedEmail,
    from_fields,
    parse_raw,
)
from phishguard.core.email.rules import run_rules as run_email_rules
from phishguard.core.explain import EMAIL_REASON, lr_reasons
from phishguard.core.risk import (
    ADVICE,
    ADVISORY_FOOTER,
    HEADLINES,
    HIGH,
    SUSPICIOUS,
    assess,
    combine_email,
    model_band,
)
from phishguard.core.url.normalize import UnsupportedURL, normalize_url
from phishguard.core.url.rules import run_rules as run_url_rules

router = APIRouter(prefix="/api/analyze/email")

UPLOAD_LIMIT = 2 * 1024 * 1024
TOO_LARGE = "That email is too large to assess."
NOT_AN_EMAIL = "That is not a valid email file."
HEADER_RULE_IDS = {"auth_fail", "reply_to_mismatch", "display_name_mismatch"}
HEADERS_UNAVAILABLE = "Header checks unavailable: paste the original email to enable them"
HEADERS_CHECKED = "Header checks ran on the original headers."
MODEL_NOTE = (
    "The email model was trained on older legitimate mail (1999-2003), so it is a weak signal "
    "for modern newsletters, receipts and notifications. Treat it as a hint, not a verdict."
)
_MAX = 2_000_000  # the parser's own size check gives the friendly message


class EmailRequest(BaseModel):
    mode: Literal["fields", "raw"] = "fields"
    subject: str = Field("", max_length=_MAX)
    sender: str = Field("", max_length=_MAX)
    body: str = Field("", max_length=_MAX)
    source: str = Field("", max_length=_MAX)


def _score_links(parsed: ParsedEmail, url_scorer) -> list[dict]:
    """Run each distinct web link through the URL pipeline, rules included."""
    mismatched = {link.href for link in anchor_mismatches(parsed.links)}
    results: list[dict] = []
    seen: set[str] = set()
    for link in parsed.links:
        if link.href in seen:
            continue
        seen.add(link.href)
        try:
            url = normalize_url(link.href)
        except UnsupportedURL:
            continue  # mailto:, javascript: and the like are not web links
        hits = run_url_rules(url)
        risk = assess(url_scorer.score(url), url_scorer.t_high, url_scorer.t_low, hits)
        results.append(
            {
                "display_host": security.defang_host(url),
                "band": risk.band,
                "headline": risk.headline,
                "lookalike": link.href in mismatched,
                "rule_warnings": [asdict(h) for h in hits],
            }
        )
    return results


def _analyze(parsed: ParsedEmail, request: Request, row: SessionRow, db: Session) -> dict:
    scorer = request.app.state.email_scorer
    if scorer is None:
        raise HTTPException(status_code=503, detail="The email model is not loaded.")
    started = perf_counter()
    url_scorer = request.app.state.url_scorer
    links = _score_links(parsed, url_scorer) if url_scorer else []

    hits = run_email_rules(parsed)
    text_band = model_band(scorer.score(parsed), scorer.t_high, scorer.t_low)
    band = combine_email(text_band, [link["band"] for link in links], hits)
    # Model reasons explain the text model, so they show only when it raised a warning itself.
    reasons = (
        lr_reasons(scorer.model, scorer.text(parsed), template=EMAIL_REASON)
        if text_band in (HIGH, SUSPICIOUS)
        else []
    )
    header_hits = [asdict(h) for h in hits if h.rule_id in HEADER_RULE_IDS]
    warnings = [asdict(h) for h in hits if h.rule_id not in HEADER_RULE_IDS]
    sender = security.defang_sender(parsed)

    db.add(
        Analysis(
            user_id=row.user_id,
            kind="email",
            input_hmac=security.email_hmac(request.app.state.settings.hmac_pepper, parsed),
            display_host=sender,
            band=band,
            model_reasons=reasons,
            rule_warnings=warnings + header_hits,
            model_version=scorer.version,
            latency_ms=round((perf_counter() - started) * 1000),
        )
    )
    db.commit()
    return {
        "band": band,
        "headline": HEADLINES[band],
        "advice": ADVICE[band],
        "footer": ADVISORY_FOOTER,
        "sender": sender,
        "model_reasons": reasons,
        "rule_warnings": warnings,
        "links": links,
        "links_checked": url_scorer is not None,
        "truncated": parsed.truncated,
        "header_checks": {
            "available": parsed.has_raw_headers,
            "message": HEADERS_CHECKED if parsed.has_raw_headers else HEADERS_UNAVAILABLE,
            "warnings": header_hits,
        },
        "model_note": MODEL_NOTE,
    }


@router.post("")
def analyze_email(
    body: EmailRequest,
    request: Request,
    row: SessionRow = Depends(auth.csrf_protected),
    db: Session = Depends(auth.get_db),
) -> dict:
    try:
        if body.mode == "raw":
            if not body.source.strip():
                raise HTTPException(status_code=422, detail="Paste the original email source.")
            parsed = parse_raw(body.source)
        else:
            if not (body.subject.strip() or body.body.strip()):
                raise HTTPException(status_code=422, detail="Enter the subject or the body.")
            parsed = from_fields(body.subject, body.sender, body.body)
    except EmailTooLarge:
        raise HTTPException(status_code=413, detail=TOO_LARGE) from None
    except NotAnEmail:
        raise HTTPException(status_code=422, detail=NOT_AN_EMAIL) from None
    return _analyze(parsed, request, row, db)


@router.post("/upload")
def analyze_email_upload(
    request: Request,
    file: Annotated[UploadFile, File()],
    row: SessionRow = Depends(auth.csrf_protected),
    db: Session = Depends(auth.get_db),
) -> dict:
    data = file.file.read(UPLOAD_LIMIT + 1)  # never read more than the cap
    if len(data) > UPLOAD_LIMIT:
        raise HTTPException(status_code=413, detail=TOO_LARGE)
    try:
        parsed = parse_raw(data)
    except EmailTooLarge:
        raise HTTPException(status_code=413, detail=TOO_LARGE) from None
    except NotAnEmail:
        raise HTTPException(status_code=422, detail=NOT_AN_EMAIL) from None
    return _analyze(parsed, request, row, db)
