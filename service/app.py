"""clear-amber-heron — the frame. Not generated; not safe to generate.

This file and the modules it imports are what make the container deploy at all:
they read each datastore URL out of the environment the Aiven integrations
inject, serve an honest ``/healthz``, mount ``/static``, configure Jinja, and
bind the port the plan declared. Cook writes it from a template and an agent
never touches it, because a mistake here costs a five-minute container build to
discover and would make the build's own smoke test lie.

**The application itself lives in ``service/pages.py``**, which *is* generated.
The contract between the two is deliberately small:

* ``pages.py`` defines ``router``, an ``APIRouter``.
* Everything it needs is on ``request.app.state``: ``settings`` — and so every
  datastore URL, one field per service, listed in ``service/settings.py`` —
  plus ``templates``, ``app_name``, ``user_intent`` and ``services``. Nothing is
  passed at import time, so the module is identical whether Cook rendered it or
  an agent wrote it.
* Its schema belongs in ``pg/001_schema.sql`` at the repository root, which Cook
  applies before this container is ever deployed.

**A broken ``pages.py`` must not crash-loop the container.** Importing it is
guarded: if it raises, the frame still starts, ``/healthz`` reports 503 naming
the import error, and ``/`` shows it. That way a bad generation produces a
deployed app that explains itself — readable from the build's Logs panel — rather
than a container that dies before anything can be read out of it. The smoke test
still fails, which is correct: the build *did* fail.
"""

from __future__ import annotations

import asyncio
import html
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from service._revision import REVISION
from service.health import Probe, probe_postgres
from service.settings import Settings, get_settings

SERVICE_DIR = Path(__file__).parent

log = logging.getLogger("clear-amber-heron")

APP_NAME = "clear-amber-heron"

# The prompt is arbitrary text, so it is inserted through `tojson`, which quotes
# and escapes it into a valid Python string literal — safe even if it contains
# quotes, backslashes or newlines. No `noqa` here: `templates/` is excluded from
# this repository's own lint, so one would never apply to the placeholder, and it
# would arrive in the generated repository as an unused directive.
USER_INTENT: str = "build a to-do app that can handle multiple advising, board and consulting engagements for 1 person with recurring calls plus add hoc and a number of offline deliverables. Recurring board meetings quarterly. What else should someone like this need here? Store this data safely in an encrypted fashion and in a way that if I need to discontinue an engagement all data can be totally wiped out, nothing left."

# The services this app was built with, per the resolved plan.
SERVICES: list[dict[str, str]] = [
    {"type": "pg", "name": "cook-heron-pg", "env_key": "DATABASE_URL"},
]


def _load_surface() -> tuple[Any, str]:
    """Import the generated router, or report why it could not be imported.

    Returns ``(router, "")`` on success and ``(None, reason)`` on failure. Never
    raises: the whole point is that the frame comes up either way.
    """
    try:
        from service.pages import router
    except Exception as exc:  # any import failure at all must be survivable
        reason = f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"
        log.error("service/pages.py failed to import: %s", reason)
        return None, reason
    return router, ""


async def _probe_all(settings: Settings) -> list[Probe]:
    """Check every datastore this app was built with, concurrently.

    Concurrently because ``/healthz`` is on the smoke test's critical path and
    each probe can take up to its own timeout: run in sequence, three unreachable
    datastores would take three times as long to report the same answer.
    """
    return list(
        await asyncio.gather(
            probe_postgres(settings.database_url),
        )
    )


async def _boot_banner(settings: Settings) -> None:
    """Log whether the datastores actually answer, once, at startup."""
    log.info("%s starting", APP_NAME)
    for probe in await _probe_all(settings):
        line = f"  {probe.name:<10} {probe.status}"
        if probe.detail:
            line += f" — {probe.detail}"
        log.info(line)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application. Pass ``settings`` to override the environment."""
    settings = settings or get_settings()
    router, surface_error = _load_surface()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await _boot_banner(settings)
        if surface_error:
            log.error("serving a diagnostic page only: %s", surface_error)
        yield
        log.info("%s stopping", APP_NAME)

    app = FastAPI(title=APP_NAME, lifespan=lifespan)
    app.state.settings = settings
    app.state.app_name = APP_NAME
    app.state.user_intent = USER_INTENT
    app.state.services = SERVICES
    app.state.templates = Jinja2Templates(directory=str(SERVICE_DIR / "templates"))
    app.state.surface_error = surface_error
    app.mount("/static", StaticFiles(directory=str(SERVICE_DIR / "static")), name="static")

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        """200 only once every datastore answers *and* the application loaded.

        Every condition, because any one failing means this build did not work —
        and the build's smoke test reads exactly this.
        """
        probes = await _probe_all(settings)
        dependencies = [{"name": p.name, "status": p.status, "detail": p.detail} for p in probes]
        dependencies.append(
            {
                "name": "application",
                "status": "failed" if surface_error else "ok",
                "detail": surface_error,
            }
        )
        healthy = all(p.healthy for p in probes) and not surface_error
        return JSONResponse(
            status_code=200 if healthy else 503,
            content={
                "status": "ok" if healthy else "degraded",
                # Which build is answering. Aiven reports no commit for a service
                # without a VCS integration, which is every app Cook generates, so
                # this is how Cook tells whether a deploy shipped the code it
                # pushed — see `service/_revision.py`. Reported whether healthy or
                # not: a degraded app is exactly when you need to know which
                # version is degraded.
                "revision": REVISION,
                "dependencies": dependencies,
            },
        )

    if router is not None:
        app.include_router(router)
    else:

        @app.get("/", response_class=HTMLResponse)
        async def broken(request: Request) -> HTMLResponse:
            """Say what went wrong, rather than showing nothing at all.

            Both values are escaped. `surface_error` is an exception message from
            generated code, and generated code is written from a prompt — so this
            string is not as trustworthy as it looks.
            """
            title = html.escape(APP_NAME)
            reason = html.escape(surface_error)
            return HTMLResponse(
                status_code=503,
                content=(
                    f"<!doctype html><title>{title}</title>"
                    f"<pre>The generated application failed to load.\n\n{reason}</pre>"
                ),
            )

    return app
