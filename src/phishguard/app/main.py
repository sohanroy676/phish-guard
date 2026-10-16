import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import sessionmaker
from starlette.exceptions import HTTPException as StarletteHTTPException

from phishguard.app.config import Settings, check_secrets, get_settings
from phishguard.app.db import make_engine
from phishguard.app.events import EventBus
from phishguard.app.models_db import Base
from phishguard.app.retention import purge_daily, purge_old
from phishguard.app.routers import analyze, analyze_email, auth, dashboard, events, history, meta
from phishguard.core.email.scoring import load_email_scorer
from phishguard.core.url.scoring import load_url_scorer

WEB_DIST = Path(__file__).resolve().parents[3] / "web" / "dist"


class SPAFiles(StaticFiles):
    """Serve the built React app, falling back to index.html for client-side routes.

    Unknown /api paths and missing files with an extension (assets) stay real 404s.
    """

    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            path = path.replace("\\", "/")  # Starlette uses os.sep
            last = path.rsplit("/", 1)[-1]
            if exc.status_code != 404 or path.startswith("api/") or "." in last:
                raise
            return await super().get_response("index.html", scope)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        check_secrets(settings)
        Base.metadata.create_all(app.state.engine)
        # A hash or version mismatch raises here, so the app refuses to start.
        if settings.model_version_url:
            app.state.url_scorer = load_url_scorer(settings.model_version_url, settings.models_dir)
        if settings.model_version_email:
            app.state.email_scorer = load_email_scorer(
                settings.model_version_email, settings.models_dir
            )
        purge_old(app.state.sessionmaker, settings.retention_days)
        purger = asyncio.create_task(purge_daily(app.state.sessionmaker, settings.retention_days))
        yield
        purger.cancel()

    app = FastAPI(title="PhishGuard", lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = make_engine(settings.database_url)
    app.state.sessionmaker = sessionmaker(app.state.engine, expire_on_commit=False)
    app.state.url_scorer = None
    app.state.email_scorer = None
    # Events live in memory, so the app must run as a single worker.
    app.state.events = EventBus()
    app.include_router(meta.router)
    app.include_router(auth.router)
    app.include_router(analyze.router)
    app.include_router(analyze_email.router)
    app.include_router(events.router)
    app.include_router(history.router)
    app.include_router(dashboard.router)
    if WEB_DIST.is_dir():
        app.mount("/", SPAFiles(directory=WEB_DIST, html=True), name="web")
    return app


app = create_app()
