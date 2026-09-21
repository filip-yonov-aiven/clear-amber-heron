# syntax=docker/dockerfile:1
#
# clear-amber-heron — built by Cook. Aiven Apps builds this from ./app/Dockerfile
# with build_path ./, the same shape Cook uses for its own container.

FROM python:3.14-slim-bookworm AS builder

# uv pinned by version, copied in rather than installed, so the build has one
# Python version and one uv version and no resolution step of its own.
COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /srv

# Dependencies first, so a source-only change reuses the layer. There is no
# committed uv.lock: this project's name only exists once Cook renders it, so
# the lock is resolved fresh at build time instead of pinned in the source.
COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-install-project --no-dev

COPY service/ ./service/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --no-dev

FROM python:3.14-slim-bookworm AS runtime

# Aiven's *.l.aivencloud.com endpoints serve Let's Encrypt certificates, which
# this image's CA bundle already trusts. Deliberately NO custom CA: setting a
# project CA breaks TLS verification against those endpoints.
RUN groupadd --system app && useradd --system --gid app --create-home app

WORKDIR /srv
COPY --from=builder --chown=app:app /srv /srv

ENV PATH="/srv/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8000

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=4).status==200 else 1)"

CMD ["python", "-m", "service"]
