"""Entry point: ``python -m service``."""

from __future__ import annotations

import logging

import uvicorn

from service.settings import get_settings


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    settings = get_settings()
    uvicorn.run(
        "service.app:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
    )


if __name__ == "__main__":
    main()
