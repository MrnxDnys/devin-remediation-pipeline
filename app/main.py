"""FastAPI app assembly: trigger layer + observability, sharing one SQLite state store."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import webhook
from .config import settings
from .db import add_event, init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    add_event("startup", f"Pipeline started in {settings.devin_mode.upper()} mode")
    yield


app = FastAPI(title="Devin Security-Remediation Pipeline", lifespan=lifespan)
app.include_router(webhook.router)

# Observability layer (dashboard + metrics + report) is a self-contained module. Include it
# when present so the pipeline runs with or without it - the module is built as its own unit.
try:
    from . import dashboard

    app.include_router(dashboard.router)
    _static = os.path.join(os.path.dirname(__file__), "static")
    if os.path.isdir(_static):
        app.mount("/static", StaticFiles(directory=_static), name="static")
except ImportError:
    pass


@app.get("/health")
async def health():
    return {"status": "ok", "mode": settings.devin_mode, "repo": settings.github_repo}
