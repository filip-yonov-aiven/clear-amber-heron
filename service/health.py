"""Dependency probes.

``GET /healthz`` is honest: it returns 200 only once every datastore this app was
built with actually answers, and 503 otherwise. A build's smoke test depends on
that being true, so a dishonest health check here would make the whole pipeline
lie.

One probe per datastore in the plan, assembled by Cook from
``templates/_stores/<type>/probe.py.j2``. Every probe is ``async`` — including
OpenSearch's, whose client is synchronous and therefore goes to a thread — so
that a slow or unreachable datastore never stalls the worker.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal

Status = Literal["ok", "unreachable", "not_configured"]

PROBE_TIMEOUT_S = 3.0


@dataclass(frozen=True, slots=True)
class Probe:
    """The result of checking one dependency."""

    name: str
    status: Status
    detail: str = ""

    @property
    def healthy(self) -> bool:
        """A dependency that is deliberately absent does not make us unhealthy."""
        return self.status in ("ok", "not_configured")


async def probe_postgres(url: str) -> Probe:
    """Check PostgreSQL answers a trivial query.

    Verifies TLS against system trust with no custom CA: Aiven's
    ``*.l.aivencloud.com`` endpoints serve Let's Encrypt certificates, which
    the slim Python image already trusts. Passing a project CA here would
    actively break verification (openssl error 20) — so this deliberately
    never does.
    """
    if not url:
        return Probe("postgres", "not_configured")
    try:
        import psycopg

        async with (
            await asyncio.wait_for(
                psycopg.AsyncConnection.connect(url), timeout=PROBE_TIMEOUT_S
            ) as conn,
            conn.cursor() as cur,
        ):
            await cur.execute("SELECT 1")
            await cur.fetchone()
        return Probe("postgres", "ok")
    except Exception as exc:
        return Probe("postgres", "unreachable", _cause(exc))


def _cause(exc: Exception) -> str:
    """A short, log-safe description of a failure.

    Connection URLs carry credentials, so only the exception type and a
    trimmed message are kept — never the URL, and never a full traceback.
    """
    message = str(exc).splitlines()[0] if str(exc) else ""
    return f"{type(exc).__name__}: {message[:120]}" if message else type(exc).__name__
