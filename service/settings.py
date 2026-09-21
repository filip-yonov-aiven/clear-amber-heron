"""Runtime configuration, read only from the environment.

Each URL below is injected by the Aiven service integration that wires that
service into this app — none is ever written into a file here, and there is no
``.env`` committed alongside this source. Local development sets them by hand
(see README.md).

The field names are not arbitrary: each is the injected environment variable in
lower case, which is how ``pydantic-settings`` maps one to the other.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """clear-amber-heron's runtime configuration."""

    #: PostgreSQL, injected as ``DATABASE_URL``.
    database_url: str = ""

    host: str = "127.0.0.1"
    port: int = int("8000")


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings, built once."""
    return Settings()
