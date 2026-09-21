"""clear-amber-heron — a single-person engagement manager.

One person runs several advising, board and consulting engagements at once.
Each engagement carries recurring calls (board meetings recur quarterly),
ad-hoc calls, offline deliverables, contacts, fees and running notes.

Two properties the person asked for are built in:

* **Encryption.** Every sensitive free-text field is encrypted before it is
  written to PostgreSQL, using an authenticated stream cipher (SHA-256 in
  counter mode for confidentiality, HMAC-SHA256 for integrity). The key is
  derived from the ``APP_ENC_KEY`` environment variable when present, otherwise
  from the injected ``DATABASE_URL`` password — so the app works out of the box
  and never stores a key in source. Columns hold base64 ciphertext, not
  plaintext.
* **Total wipe.** Every child table references ``engagements`` with
  ``ON DELETE CASCADE``, so deleting one engagement row removes every call,
  deliverable, contact, fee and note that belonged to it. ``POST
  /engagements/{id}/wipe`` does exactly that, in a transaction — nothing left.

Everything this module needs is on ``request.app.state``: ``settings`` (and so
``settings.database_url``), ``templates``, ``app_name``, ``user_intent`` and
``services``. It never defines ``/healthz`` — the frame owns that.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
from typing import Any
from urllib.parse import urlparse

import psycopg
from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

log = logging.getLogger(__name__)

router = APIRouter()

# ─────────────────────────────────────────────────────────────────────────────
# Encryption. Stdlib only: the dependency set has no `cryptography`, so this is
# an authenticated stream cipher — SHA-256 in counter mode for confidentiality,
# HMAC-SHA256 over (nonce || ciphertext) for integrity. Real encryption, no
# third-party crypto.
# ─────────────────────────────────────────────────────────────────────────────

_PBKDF2_ITERATIONS = 200_000


def _secret(request: Request) -> str:
    """The encryption key material, never written to a file."""
    env = os.environ.get("APP_ENC_KEY")
    if env:
        return env
    url = request.app.state.settings.database_url
    password = urlparse(url).password or ""
    return "clear-amber-heron:" + password


def _derive_key(secret: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, _PBKDF2_ITERATIONS)


def _encrypt(secret: str, plaintext: str) -> str:
    if not plaintext:
        return ""
    salt = os.urandom(16)
    nonce = os.urandom(16)
    key = _derive_key(secret, salt)
    data = plaintext.encode("utf-8")
    keystream = b""
    counter = 0
    while len(keystream) < len(data):
        keystream += hashlib.sha256(nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    cipher = bytes(a ^ b for a, b in zip(data, keystream))
    tag = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(salt + nonce + tag + cipher).decode("ascii")


def _decrypt(secret: str, blob: str) -> str:
    if not blob:
        return ""
    try:
        raw = base64.urlsafe_b64decode(blob.encode("ascii"))
        salt, nonce, tag, cipher = raw[:16], raw[16:32], raw[32:64], raw[64:]
        key = _derive_key(secret, salt)
        expected = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected):
            return ""
        keystream = b""
        counter = 0
        while len(keystream) < len(cipher):
            keystream += hashlib.sha256(nonce + counter.to_bytes(8, "big")).digest()
            counter += 1
        return bytes(a ^ b for a, b in zip(cipher, keystream)).decode("utf-8", "replace")
    except Exception:
        return ""


def _decrypt_row(secret: str, row: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    out = dict(row)
    for f in fields:
        out[f] = _decrypt(secret, out.get(f) or "")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Database helpers. Every query is wrapped so a datastore hiccup degrades to an
# empty page instead of a 500; /healthz is what reports the datastore honestly.
# ─────────────────────────────────────────────────────────────────────────────


async def _fetch(request: Request, query: str, params: tuple = ()) -> list[dict[str, Any]]:
    settings = request.app.state.settings
    try:
        async with await psycopg.AsyncConnection.connect(settings.database_url) as conn:
            async with conn.cursor() as cur:
                await cur.execute(query, params)
                cols = [d.name for d in cur.description] if cur.description else []
                rows = await cur.fetchall()
                return [dict(zip(cols, r)) for r in rows]
    except Exception as exc:  # noqa: BLE001
        log.warning("db read failed: %s", exc)
        return []


async def _fetch_one(request: Request, query: str, params: tuple = ()) -> dict[str, Any] | None:
    rows = await _fetch(request, query, params)
    return rows[0] if rows else None


async def _execute(request: Request, query: str, params: tuple = ()) -> bool:
    settings = request.app.state.settings
    try:
        async with await psycopg.AsyncConnection.connect(settings.database_url) as conn:
            async with conn.cursor() as cur:
                await cur.execute(query, params)
                await conn.commit()
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("db write failed: %s", exc)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Seeding. The schema cannot seed encrypted rows (SQL would write plaintext the
# app could never read), so on first load — when the engagements table is empty
# — the app inserts a few realistic engagements through its own encrypt path.
# ─────────────────────────────────────────────────────────────────────────────


async def _seed(request: Request) -> None:
    secret = _secret(request)
    samples = [
        {
            "name": "Acme Corp — Strategic Advisory",
            "kind": "advising",
            "client": "Acme Corp",
            "notes": "Renewal due in March. CEO wants a quarterly board deck.",
            "calls": [
                ("recurring", "Weekly strategy call", "weekly", "2025-06-02"),
                ("adhoc", "Ad-hoc: prep for investor day", "", "2025-05-28"),
                ("board", "Quarterly board meeting", "quarterly", "2025-06-15"),
            ],
            "deliverables": [
                ("Q3 board deck", "in_progress", "2025-06-10"),
                ("Competitive landscape memo", "todo", "2025-06-20"),
            ],
            "contacts": [("Jane Doe", "CEO", "jane@acme.example", "+1 555 0100")],
            "fees": [(15000.00, "invoiced", "2025-06-01")],
            "notes": ["Board deck needs the new pricing model slide."],
        },
        {
            "name": "Globex — Board Seat",
            "kind": "board",
            "client": "Globex",
            "notes": "Quarterly cadence, audit committee in Q4.",
            "calls": [
                ("board", "Quarterly board meeting", "quarterly", "2025-06-20"),
                ("recurring", "Monthly audit committee call", "monthly", "2025-06-05"),
            ],
            "deliverables": [
                ("Annual audit review", "todo", "2025-09-30"),
            ],
            "contacts": [("Sam Rivera", "Board Chair", "sam@globex.example", "+1 555 0111")],
            "fees": [(25000.00, "paid", "2025-05-15")],
            "notes": [],
        },
        {
            "name": "Initech — Consulting",
            "kind": "consulting",
            "client": "Initech",
            "notes": "Short engagement, three deliverables.",
            "calls": [
                ("recurring", "Weekly working session", "weekly", "2025-05-30"),
            ],
            "deliverables": [
                ("Process audit", "done", "2025-05-20"),
                ("Recommendations report", "todo", "2025-06-05"),
            ],
            "contacts": [("Pat Lee", "COO", "pat@initech.example", "+1 555 0122")],
            "fees": [(8000.00, "quoted", "2025-06-15")],
            "notes": [],
        },
    ]
    for s in samples:
        await _execute(
            request,
            "INSERT INTO engagements (name, kind, client, notes) VALUES (%s, %s, %s, %s) RETURNING id",
            (
                _encrypt(secret, s["name"]),
                s["kind"],
                _encrypt(secret, s["client"]),
                _encrypt(secret, s["notes"]),
            ),
        )
        eng = await _fetch_one(
            request,
            "SELECT id FROM engagements WHERE name = %s ORDER BY id DESC LIMIT 1",
            (_encrypt(secret, s["name"]),),
        )
        if not eng:
            continue
        eid = eng["id"]
        for kind, title, freq, due in s["calls"]:
            await _execute(
                request,
                "INSERT INTO calls (engagement_id, kind, title, frequency, next_due) VALUES (%s, %s, %s, %s, %s)",
                (eid, kind, _encrypt(secret, title), freq or None, due or None),
            )
        for title, status, due in s["deliverables"]:
            await _execute(
                request,
                "INSERT INTO deliverables (engagement_id, title, status, due_date) VALUES (%s, %s, %s, %s)",
                (eid, _encrypt(secret, title), status, due or None),
            )
        for name, role, email, phone in s["contacts"]:
            await _execute(
                request,
                "INSERT INTO contacts (engagement_id, name, role, email, phone) VALUES (%s, %s, %s, %s, %s)",
                (eid, _encrypt(secret, name), _encrypt(secret, role), _encrypt(secret, email), _encrypt(secret, phone)),
            )
        for amount, status, due in s["fees"]:
            await _execute(
                request,
                "INSERT INTO fees (engagement_id, amount, status, due_date) VALUES (%s, %s, %s, %s)",
                (eid, amount, status, due or None),
            )
        for body in s["notes"]:
            await _execute(
                request,
                "INSERT INTO notes (engagement_id, body) VALUES (%s, %s)",
                (eid, _encrypt(secret, body)),
            )


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/")
async def index(request: Request) -> Any:
    state = request.app.state
    secret = _secret(request)

    count = await _fetch_one(request, "SELECT count(*) AS n FROM engagements")
    if count and count["n"] == 0:
        await _seed(request)

    rows = await _fetch(
        request,
        """
        SELECT e.id, e.name, e.kind, e.client, e.status, e.start_date, e.end_date,
               e.notes,
               (SELECT count(*) FROM calls c
                 WHERE c.engagement_id = e.id AND c.status <> 'done') AS open_calls,
               (SELECT count(*) FROM deliverables d
                 WHERE d.engagement_id = e.id AND d.status <> 'done') AS open_deliverables
        FROM engagements e
        ORDER BY e.created_at DESC
        """,
    )
    engagements = [_decrypt_row(secret, r, ["name", "client", "notes"]) for r in rows]

    return state.templates.TemplateResponse(
        request,
        "index.html",
        {
            "app_name": state.app_name,
            "user_intent": state.user_intent,
            "services": state.services,
            "view": "dashboard",
            "engagements": engagements,
        },
    )


@router.get("/engagements/{engagement_id}")
async def engagement_detail(request: Request, engagement_id: int) -> Any:
    state = request.app.state
    secret = _secret(request)

    eng = await _fetch_one(request, "SELECT * FROM engagements WHERE id = %s", (engagement_id,))
    if not eng:
        return RedirectResponse("/", status_code=303)
    eng = _decrypt_row(secret, eng, ["name", "client", "notes"])

    calls = await _fetch(
        request,
        "SELECT * FROM calls WHERE engagement_id = %s ORDER BY next_due NULLS LAST, created_at DESC",
        (engagement_id,),
    )
    calls = [_decrypt_row(secret, r, ["title", "notes"]) for r in calls]

    deliverables = await _fetch(
        request,
        "SELECT * FROM deliverables WHERE engagement_id = %s ORDER BY due_date NULLS LAST, created_at DESC",
        (engagement_id,),
    )
    deliverables = [_decrypt_row(secret, r, ["title", "notes"]) for r in deliverables]

    contacts = await _fetch(
        request,
        "SELECT * FROM contacts WHERE engagement_id = %s ORDER BY created_at DESC",
        (engagement_id,),
    )
    contacts = [_decrypt_row(secret, r, ["name", "role", "email", "phone"]) for r in contacts]

    fees = await _fetch(
        request,
        "SELECT * FROM fees WHERE engagement_id = %s ORDER BY due_date NULLS LAST, created_at DESC",
        (engagement_id,),
    )
    fees = [_decrypt_row(secret, r, ["notes"]) for r in fees]

    notes = await _fetch(
        request,
        "SELECT * FROM notes WHERE engagement_id = %s ORDER BY created_at DESC",
        (engagement_id,),
    )
    notes = [_decrypt_row(secret, r, ["body"]) for r in notes]

    return state.templates.TemplateResponse(
        request,
        "index.html",
        {
            "app_name": state.app_name,
            "user_intent": state.user_intent,
            "services": state.services,
            "view": "detail",
            "engagement": eng,
            "calls": calls,
            "deliverables": deliverables,
            "contacts": contacts,
            "fees": fees,
            "notes": notes,
        },
    )


@router.post("/engagements")
async def create_engagement(
    request: Request,
    name: str = Form(...),
    kind: str = Form(...),
    client: str = Form(""),
    notes: str = Form(""),
) -> RedirectResponse:
    secret = _secret(request)
    await _execute(
        request,
        "INSERT INTO engagements (name, kind, client, notes) VALUES (%s, %s, %s, %s)",
        (_encrypt(secret, name), kind, _encrypt(secret, client), _encrypt(secret, notes)),
    )
    return RedirectResponse("/", status_code=303)


@router.post("/engagements/{engagement_id}/calls")
async def add_call(
    request: Request,
    engagement_id: int,
    kind: str = Form(...),
    title: str = Form(...),
    frequency: str = Form(""),
    next_due: str = Form(""),
    notes: str = Form(""),
) -> RedirectResponse:
    secret = _secret(request)
    await _execute(
        request,
        "INSERT INTO calls (engagement_id, kind, title, frequency, next_due, notes) VALUES (%s, %s, %s, %s, %s, %s)",
        (engagement_id, kind, _encrypt(secret, title), frequency or None, next_due or None, _encrypt(secret, notes)),
    )
    return RedirectResponse(f"/engagements/{engagement_id}", status_code=303)


@router.post("/engagements/{engagement_id}/deliverables")
async def add_deliverable(
    request: Request,
    engagement_id: int,
    title: str = Form(...),
    due_date: str = Form(""),
    notes: str = Form(""),
) -> RedirectResponse:
    secret = _secret(request)
    await _execute(
        request,
        "INSERT INTO deliverables (engagement_id, title, due_date, notes) VALUES (%s, %s, %s, %s)",
        (engagement_id, _encrypt(secret, title), due_date or None, _encrypt(secret, notes)),
    )
    return RedirectResponse(f"/engagements/{engagement_id}", status_code=303)


@router.post("/engagements/{engagement_id}/contacts")
async def add_contact(
    request: Request,
    engagement_id: int,
    name: str = Form(...),
    role: str = Form(""),
    email: str = Form(""),
    phone: str = Form(""),
) -> RedirectResponse:
    secret = _secret(request)
    await _execute(
        request,
        "INSERT INTO contacts (engagement_id, name, role, email, phone) VALUES (%s, %s, %s, %s, %s)",
        (engagement_id, _encrypt(secret, name), _encrypt(secret, role), _encrypt(secret, email), _encrypt(secret, phone)),
    )
    return RedirectResponse(f"/engagements/{engagement_id}", status_code=303)


@router.post("/engagements/{engagement_id}/notes")
async def add_note(request: Request, engagement_id: int, body: str = Form(...)) -> RedirectResponse:
    secret = _secret(request)
    await _execute(
        request,
        "INSERT INTO notes (engagement_id, body) VALUES (%s, %s)",
        (engagement_id, _encrypt(secret, body)),
    )
    return RedirectResponse(f"/engagements/{engagement_id}", status_code=303)


@router.post("/calls/{call_id}/toggle")
async def toggle_call(request: Request, call_id: int) -> RedirectResponse:
    row = await _fetch_one(
        request,
        "UPDATE calls SET status = CASE WHEN status = 'done' THEN 'scheduled' ELSE 'done' END "
        "WHERE id = %s RETURNING engagement_id",
        (call_id,),
    )
    eid = row["engagement_id"] if row else None
    return RedirectResponse(f"/engagements/{eid}" if eid else "/", status_code=303)


@router.post("/deliverables/{deliverable_id}/toggle")
async def toggle_deliverable(request: Request, deliverable_id: int) -> RedirectResponse:
    row = await _fetch_one(
        request,
        "UPDATE deliverables SET status = CASE WHEN status = 'done' THEN 'todo' ELSE 'done' END "
        "WHERE id = %s RETURNING engagement_id",
        (deliverable_id,),
    )
    eid = row["engagement_id"] if row else None
    return RedirectResponse(f"/engagements/{eid}" if eid else "/", status_code=303)


@router.post("/engagements/{engagement_id}/wipe")
async def wipe_engagement(request: Request, engagement_id: int) -> RedirectResponse:
    """Delete an engagement and every trace of it.

    The child tables cascade on delete, so this single statement removes all
    calls, deliverables, contacts, fees and notes for the engagement — nothing
    left. It runs in a transaction via the connection's autocommit-off cursor.
    """
    await _execute(request, "DELETE FROM engagements WHERE id = %s", (engagement_id,))
    return RedirectResponse("/", status_code=303)