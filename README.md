# clear-amber-heron

A FastAPI app with PostgreSQL, scaffolded by Cook.

Built from: build a to-do app that can handle multiple advising, board and consulting engagements for 1 person with recurring calls plus add hoc and a number of offline deliverables. Recurring board meetings quarterly. What else should someone like this need here? Store this data safely in an encrypted fashion and in a way that if I need to discontinue an engagement all data can be totally wiped out, nothing left.

## What's here

- `service/pages.py` — **the application**, and the one file an agent writes.
  What ships in a fresh scaffold is a placeholder that says so.
- `service/app.py` — the frame: reads the environment, serves `/healthz`, mounts
  static files, and survives a `pages.py` that fails to import.
- `service/health.py` — one probe per datastore, which `/healthz` depends on.
- `service/settings.py` — configuration, read only from the environment.
- `service/templates/index.html` — the page shell, styled with the Aiven brand
  tokens in `service/static/tokens.css`.
- `pg/001_schema.sql` — the schema, applied by Cook before this app is deployed.
- `app/Dockerfile` — the container this ships as.

## Services wired in

| Service | Name | Reaches this app as |
|---|---|---|
| pg | `cook-heron-pg` | `DATABASE_URL` |
| application | `clear-amber-heron` | `` |

Each variable above is injected by an Aiven service integration once this app is
deployed. None is written into a file in this repository — there is no `.env`
committed here, and none should ever be added.

## Running locally

```bash
export DATABASE_URL=...   # PostgreSQL
uv sync
uv run python -m service
```

Visit `http://localhost:8000`. `GET /healthz` returns `200` once every
datastore answers, and `503` otherwise — stop one to see the honest failure mode.

## Building the container

```bash
docker build -f app/Dockerfile -t clear-amber-heron .
docker run -p 8000:8000 \
    -e DATABASE_URL=... \
    clear-amber-heron
```

TLS to Aiven's `*.l.aivencloud.com` endpoints verifies against the system
trust store already present in `python:3.14-slim-bookworm` — no custom CA is
configured, and none should be added.
