from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import sessionmaker

from phishguard.app.config import Settings, check_secrets, get_settings
from phishguard.app.db import make_engine
from phishguard.app.models_db import Base
from phishguard.app.routers import analyze, auth, meta
from phishguard.core.url.scoring import load_url_scorer

WEB_DIST = Path(__file__).resolve().parents[3] / "web" / "dist"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        check_secrets(settings)
        Base.metadata.create_all(app.state.engine)
        # A hash or version mismatch raises here, so the app refuses to start.
        if settings.model_version_url:
            app.state.url_scorer = load_url_scorer(settings.model_version_url, settings.models_dir)
        yield

    app = FastAPI(title="PhishGuard", lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = make_engine(settings.database_url)
    app.state.sessionmaker = sessionmaker(app.state.engine, expire_on_commit=False)
    app.state.url_scorer = None
    app.include_router(meta.router)
    app.include_router(auth.router)
    app.include_router(analyze.router)
    if WEB_DIST.is_dir():
        app.mount("/", StaticFiles(directory=WEB_DIST, html=True), name="web")
    return app


app = create_app()
