"""Password hashing, server-side sessions and the request dependencies that enforce them."""

import re
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from phishguard.app import security
from phishguard.app.models_db import SessionRow, User

SESSION_COOKIE = "phishguard_session"
CSRF_HEADER = "X-CSRF-Token"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD, MAX_PASSWORD = 10, 128

_hasher = PasswordHasher()  # Argon2id
# Verified when the email is unknown, so login timing does not reveal which emails exist.
_DUMMY_HASH = _hasher.hash("not-a-real-password")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    try:
        ok = _hasher.verify(stored_hash or _DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return False
    return ok and stored_hash is not None


def get_db(request: Request):
    with request.app.state.sessionmaker() as db:
        yield db


def create_session(db: Session, settings, user_id: int) -> tuple[str, SessionRow]:
    token = security.new_token()
    row = SessionRow(
        token_hash=security.token_hash(settings.secret_key, token),
        user_id=user_id,
        csrf_token=security.new_token(),
        expires_at=datetime.now(UTC) + timedelta(hours=settings.session_hours),
    )
    db.add(row)
    db.commit()
    return token, row


def _load_session(request: Request, db: Session) -> SessionRow | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    digest = security.token_hash(request.app.state.settings.secret_key, token)
    row = db.scalar(select(SessionRow).where(SessionRow.token_hash == digest))
    if row is None:
        return None
    expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=UTC)
    if expires <= datetime.now(UTC):
        db.delete(row)
        db.commit()
        return None
    return row


def current_session(request: Request, db: Session = Depends(get_db)) -> SessionRow:
    row = _load_session(request, db)
    if row is None:
        raise HTTPException(status_code=401, detail="Please log in.")
    return row


def csrf_protected(request: Request, row: SessionRow = Depends(current_session)) -> SessionRow:
    if not security.csrf_ok(row.csrf_token, request.headers.get(CSRF_HEADER)):
        raise HTTPException(status_code=403, detail="Missing or invalid CSRF token.")
    return row


def current_user(row: SessionRow = Depends(current_session), db: Session = Depends(get_db)) -> User:
    user = db.get(User, row.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Please log in.")
    return user
