from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from phishguard.app import auth
from phishguard.app.models_db import SessionRow, User

router = APIRouter(prefix="/api")


class Credentials(BaseModel):
    email: str
    password: str


class Registration(Credentials):
    consent: bool = False


def _clean_email(raw: str) -> str:
    email = raw.strip().lower()
    if len(email) > 254 or not auth.EMAIL_RE.match(email):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    return email


def _start_session(request: Request, response: Response, db: Session, user: User) -> dict:
    settings = request.app.state.settings
    token, row = auth.create_session(db, settings, user.id)
    response.set_cookie(
        auth.SESSION_COOKIE,
        token,
        max_age=settings.session_hours * 3600,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
    )
    return {"email": user.email, "csrf_token": row.csrf_token}


# Register and login take JSON only and the cookie is SameSite=Lax, so they carry no CSRF token.
@router.post("/auth/register", status_code=201)
def register(
    body: Registration, request: Request, response: Response, db: Session = Depends(auth.get_db)
) -> dict:
    email = _clean_email(body.email)
    if not body.consent:
        raise HTTPException(
            status_code=422, detail="You must agree to the privacy terms to create an account."
        )
    if not auth.MIN_PASSWORD <= len(body.password) <= auth.MAX_PASSWORD:
        raise HTTPException(
            status_code=422,
            detail=f"Password must be {auth.MIN_PASSWORD} to {auth.MAX_PASSWORD} characters.",
        )
    user = User(
        email=email,
        password_hash=auth.hash_password(body.password),
        consent_at=datetime.now(UTC),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409, detail="An account with this email already exists."
        ) from None
    return _start_session(request, response, db, user)


@router.post("/auth/login")
def login(
    body: Credentials, request: Request, response: Response, db: Session = Depends(auth.get_db)
) -> dict:
    user = db.scalar(select(User).where(User.email == body.email.strip().lower()))
    if not auth.verify_password(user.password_hash if user else None, body.password):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    return _start_session(request, response, db, user)


@router.post("/auth/logout", status_code=204)
def logout(
    response: Response,
    row: SessionRow = Depends(auth.csrf_protected),
    db: Session = Depends(auth.get_db),
) -> None:
    db.delete(row)
    db.commit()
    response.delete_cookie(auth.SESSION_COOKIE, path="/")


@router.get("/me")
def me(user: User = Depends(auth.current_user), row: SessionRow = Depends(auth.current_session)):
    return {"email": user.email, "csrf_token": row.csrf_token}
