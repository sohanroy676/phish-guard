from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from phishguard.app.config import Settings, get_settings
from phishguard.app.db import make_engine
from phishguard.app.routers import meta

WEB_DIST = Path(__file__).resolve().parents[3] / "web" / "dist"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(title="PhishGuard")
    app.state.settings = settings
    app.state.engine = make_engine(settings.database_url)
    app.include_router(meta.router)
    if WEB_DIST.is_dir():
        app.mount("/", StaticFiles(directory=WEB_DIST, html=True), name="web")
    return app


app = create_app()
