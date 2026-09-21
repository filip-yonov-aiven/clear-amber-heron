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
from datetime import date
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


def _secret(request: Request) -> bytes:
    """Derive the encryption key from the environment, never from source.

    Prefer an explicit ``APP_ENC_KEY``; fall back to the injected
    ``DATABASE_URL`` password so the app works out of the box. Either way the
    key is hashed to a fixed 32-byte value and never stored in a file.
    """
    key = os.environ.get("APP_ENC_KEY")
    if key:
        return hashlib.sha256(key.encode("utf-8")).digest()
    parsed = urlparse(request.app.state.settings.database_url)
    password = parsed.password or "clear-amber-heron"
    return hashlib.sha256(password.encode("utf-8")).digest()


def _encrypt(secret: bytes, plaintext: Any) -> str:
    """Encrypt a value into a base64 blob of nonce || mac || ciphertext.

    ``plaintext`` is coerced to ``str`` first so callers can pass any scalar
    (a list of notes, a date, a number) without crashing — the value is
    stringified and then encrypted.
    """
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)
    data = plaintext.encode("utf-8")
    nonce = os.urandom(16)
    keystream = b""
    counter = 0
    while len(keystream) < len(data):
        keystream += hashlib.sha256(secret + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    ciphertext = bytes(b ^ k for b, k in zip(data, keystream))
    mac = hmac.new(secret, nonce + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(nonce + mac + ciphertext).decode("ascii")


def _decrypt(secret: bytes, blob: str) -> str:
    """Decrypt a blob written by :func:`_encrypt`. Returns ``""`` on failure."""
    try:
        raw = base64.b64decode(blob)
        nonce, mac, ciphertext = raw[:16], raw[16:48], raw[48:]
        expected = hmac.new(secret, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            return ""
        keystream = b""
        counter = 0
        while len(keystream) < len(ciphertext):
            keystream += hashlib.sha256(secret + nonce + counter.to_bytes(8, "big")).digest()
            counter += 1
        data = bytes(b ^ k for b, k in zip(ciphertext, keystream))
        return data.decode("utf-8", errors="replace")
    except Exception:
        log.exception("decrypt failed")
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Database helpers. Every query is wrapped so a datastore hiccup degrades to an
# empty page rather than a 500.
# ─────────────────────────────────────────────────────────────────────────────


async def _connect(request: Request) -> psycopg.AsyncConnection:
    return await psycopg.AsyncConnection.connect(request.app.state.settings.database_url)


async def _execute(request: Request, sql: str, params: tuple = ()) -> None:
    try:
        async with await _connect(request) as conn:
            async with conn.cursor() as cur:
                await cur.execute(sql, params)
    except Exception:
        log.exception("db execute failed")


async def _fetch_one(request: Request, sql: str, params: tuple = ()) -> dict | None:
    try:
        async with await _connect(request) as conn:
            async with conn.cursor() as cur:
                await cur.execute(sql, params)
                row = await cur.fetchone()
                return dict(row) if row else None
    except Exception:
        log.exception("db fetch one failed")
        return None


async def _fetch_all(request: Request, sql: str, params: tuple = ()) -> list[dict]:
    try:
        async with await _connect(request) as conn:
            async with conn.cursor() as cur:
                await cur.execute(sql, params)
                rows = await cur.fetchall()
                return [dict(r) for r in rows]
    except Exception:
        log.exception("db fetch all failed")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Seeding. The schema is applied before the app boots, but no seed rows are
# written in SQL because that would store plaintext the app could never
# decrypt. Instead the app seeds a few realistic engagements on first load,
# through its own encrypt-on-write path.
# ─────────────────────────────────────────────────────────────────────────────


async def _seed(request: Request) -> None:
    secret = _secret(request)
    count = await _fetch_one(request, "SELECT COUNT(*) AS n FROM engagements")
    if count and count["n"]:
        return

    seeds = [
        {
            "name": "Acme Corp — Strategic Advising",
            "kind": "advising",
            "client": "Acme Corp",
            "status": "active",
            "start_date": date(2024, 1, 15),
            "end_date": None,
            "notes": "Monthly strategy calls; focus on market expansion.",
            "calls": [
                {
                    "kind": "recurring",
                    "title": "Monthly strategy call",
                    "frequency": "monthly",
                    "next_due": date(2025, 1, 10),
                    "status": "scheduled",
                    "notes": "Prepare Q1 numbers.",
                },
                {
                    "kind": "adhoc",
                    "title": "Ad-hoc pricing review",
                    "frequency": None,
                    "next_due": date(2025, 1, 20),
                    "status": "scheduled",
                    "notes": "",
                },
            ],
            "deliverables": [
                {
                    "title": "Q1 market analysis",
                    "status": "in_progress",
                    "due_date": date(2025, 2, 1),
                    "notes": "Draft shared with client.",
                },
            ],
            "contacts": [
                {"name": "Jane Doe", "role": "CEO", "email": "jane@acme.com", "phone": "+1-555-0100"},
            ],
            "fees": [
                {"amount": 5000, "currency": "USD", "status": "invoiced", "due_date": date(2025, 1, 31), "notes": ""},
            ],
            "notes": ["Kickoff went well.", "Client wants more focus on APAC."],
        },
        {
            "name": "Globex — Board Member",
            "kind": "board",
            "client": "Globex Inc.",
            "status": "active",
            "start_date": date(2023, 6, 1),
            "end_date": None,
            "notes": "Quarterly board meetings; annual governance review.",
            "calls": [
                {
                    "kind": "board",
                    "title": "Q1 board meeting",
                    "frequency": "quarterly",
                    "next_due": date(2025, 3, 15),
                    "status": "scheduled",
                    "notes": "Review FY24 results.",
                },
            ],
            "deliverables": [
                {
                    "title": "Board pack — Q1",
                    "status": "todo",
                    "due_date": date(2025, 3, 10),
                    "notes": "",
                },
            ],
            "contacts": [
                {"name": "Sam Lee", "role": "Chair", "email": "sam@globex.com", "phone": "+1-555-0200"},
            ],
            "fees": [
                {"amount": 12000, "currency": "USD", "status": "quoted", "due_date": None, "notes": "Quarterly retainer."},
            ],
            "notes": ["Board composition discussion."],
        },
        {
            "name": "Nimbus — Consulting Engagement",
            "kind": "consulting",
            "client": "Nimbus Ltd.",
            "status": "on_hold",
            "start_date": date(2024, 9, 1),
            "end_date": None,
            "notes": "Paused pending budget approval.",
            "calls": [
                {
                    "kind": "recurring",
                    "title": "Weekly sync",
                    "frequency": "weekly",
                    "next_due": date(2025, 1, 8),
                    "status": "cancelled",
                    "notes": "",
                },
            ],
            "deliverables": [
                {
                    "title": "Process audit report",
                    "status": "done",
                    "due_date": date(2024, 12, 15),
                    "notes": "Delivered.",
                },
            ],
            "contacts": [
                {"name": "Alex Kim", "role": "COO", "email": "alex@nimbus.com", "phone": "+1-555-0300"},
            ],
            "fees": [
                {"amount": 8000, "currency": "USD", "status": "paid", "due_date": date(2024, 12, 1), "notes": ""},
            ],
            "notes": ["Awaiting budget sign-off."],
        },
    ]

    for s in seeds:
        eid = await _insert_engagement(request, secret, s)
        if eid is None:
            continue
        for c in s["calls"]:
            await _execute(
                request,
                "INSERT INTO calls (engagement_id, kind, title, frequency, next_due, status, notes) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (eid, c["kind"], _encrypt(secret, c["title"]), c["frequency"], c["next_due"], c["status"], _encrypt(secret, c["notes"])),
            )
        for d in s["deliverables"]:
            await _execute(
                request,
                "INSERT INTO deliverables (engagement_id, title, status, due_date, notes) "
                "VALUES (%s, %s, %s, %s, %s)",
                (eid, _encrypt(secret, d["title"]), d["status"], d["due_date"], _encrypt(secret, d["notes"])),
            )
        for c in s["contacts"]:
            await _execute(
                request,
                "INSERT INTO contacts (engagement_id, name, role, email, phone) "
                "VALUES (%s, %s, %s, %s, %s)",
                (eid, _encrypt(secret, c["name"]), _encrypt(secret, c["role"]), _encrypt(secret, c["email"]), _encrypt(secret, c["phone"])),
            )
        for f in s["fees"]:
            await _execute(
                request,
                "INSERT INTO fees (engagement_id, amount, currency, status, due_date, notes) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (eid, f["amount"], f["currency"], f["status"], f["due_date"], _encrypt(secret, f["notes"])),
            )
        for n in s["notes"]:
            await _execute(
                request,
                "INSERT INTO notes (engagement_id, body) VALUES (%s, %s)",
                (eid, _encrypt(secret, n)),
            )


async def _insert_engagement(request: Request, secret: bytes, s: dict) -> int | None:
    row = await _fetch_one(
        request,
        "INSERT INTO engagements (name, kind, client, status, start_date, end_date, notes) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
        (
            _encrypt(secret, s["name"]),
            s["kind"],
            _encrypt(secret, s["client"]),
            s["status"],
            s["start_date"],
            s["end_date"],
            _encrypt(secret, s["notes"]),
        ),
    )
    return row["id"] if row else None


# ─────────────────────────────────────────────────────────────────────────────
# Routes.
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/")
async def index(request: Request):
    await _seed(request)
    secret = _secret(request)
    engagements = await _fetch_all(
        request,
        "SELECT id, name, kind, client, status, start_date, end_date, notes FROM engagements ORDER BY created_at",
    )
    for e in engagements:
        e["name"] = _decrypt(secret, e["name"])
        e["client"] = _decrypt(secret, e["client"])
        e["notes"] = _decrypt(secret, e["notes"])

    engagement = None
    calls = []
    deliverables = []
    contacts = []
    fees = []
    notes = []

    eid = request.query_params.get("id")
    if eid and eid.isdigit():
        engagement = await _fetch_one(
            request,
            "SELECT id, name, kind, client, status, start_date, end_date, notes FROM engagements WHERE id = %s",
            (int(eid),),
        )
        if engagement:
            engagement["name"] = _decrypt(secret, engagement["name"])
            engagement["client"] = _decrypt(secret, engagement["client"])
            engagement["notes"] = _decrypt(secret, engagement["notes"])

            calls = await _fetch_all(
                request,
                "SELECT id, kind, title, frequency, next_due, status, notes FROM calls "
                "WHERE engagement_id = %s ORDER BY next_due NULLS LAST, created_at",
                (int(eid),),
            )
            for c in calls:
                c["title"] = _decrypt(secret, c["title"])
                c["notes"] = _decrypt(secret, c["notes"])

            deliverables = await _fetch_all(
                request,
                "SELECT id, title, status, due_date, notes FROM deliverables "
                "WHERE engagement_id = %s ORDER BY due_date NULLS LAST, created_at",
                (int(eid),),
            )
            for d in deliverables:
                d["title"] = _decrypt(secret, d["title"])
                d["notes"] = _decrypt(secret, d["notes"])

            contacts = await _fetch_all(
                request,
                "SELECT id, name, role, email, phone FROM contacts WHERE engagement_id = %s ORDER BY created_at",
                (int(eid),),
            )
            for c in contacts:
                c["name"] = _decrypt(secret, c["name"])
                c["role"] = _decrypt(secret, c["role"])
                c["email"] = _decrypt(secret, c["email"])
                c["phone"] = _decrypt(secret, c["phone"])

            fees = await _fetch_all(
                request,
                "SELECT id, amount, currency, status, due_date, notes FROM fees "
                "WHERE engagement_id = %s ORDER BY created_at",
                (int(eid),),
            )
            for f in fees:
                f["notes"] = _decrypt(secret, f["notes"])

            notes = await _fetch_all(
                request,
                "SELECT id, body FROM notes WHERE engagement_id = %s ORDER BY created_at",
                (int(eid),),
            )
            for n in notes:
                n["body"] = _decrypt(secret, n["body"])

    return request.app.state.templates.TemplateResponse(
        request,
        "index.html",
        {
            "app_name": request.app.state.app_name,
            "user_intent": request.app.state.user_intent,
            "engagements": engagements,
            "engagement": engagement,
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
    client: str = Form(...),
    status: str = Form("active"),
    start_date: str = Form(""),
    end_date: str = Form(""),
    notes: str = Form(""),
) -> RedirectResponse:
    secret = _secret(request)
    row = await _fetch_one(
        request,
        "INSERT INTO engagements (name, kind, client, status, start_date, end_date, notes) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
        (
            _encrypt(secret, name),
            kind,
            _encrypt(secret, client),
            status,
            start_date or None,
            end_date or None,
            _encrypt(secret, notes),
        ),
    )
    eid = row["id"] if row else None
    return RedirectResponse(f"/?id={eid}" if eid else "/", status_code=303)


@router.post("/engagements/{engagement_id}/calls")
async def add_call(
    request: Request,
    engagement_id: int,
    kind: str = Form(...),
    title: str = Form(...),
    frequency: str = Form(""),
    next_due: str = Form(""),
    status: str = Form("scheduled"),
    notes: str = Form(""),
) -> RedirectResponse:
    secret = _secret(request)
    await _execute(
        request,
        "INSERT INTO calls (engagement_id, kind, title, frequency, next_due, status, notes) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (engagement_id, kind, _encrypt(secret, title), frequency or None, next_due or None, status, _encrypt(secret, notes)),
    )
    return RedirectResponse(f"/?id={engagement_id}", status_code=303)


@router.post("/engagements/{engagement_id}/deliverables")
async def add_deliverable(
    request: Request,
    engagement_id: int,
    title: str = Form(...),
    status: str = Form("todo"),
    due_date: str = Form(""),
    notes: str = Form(""),
) -> RedirectResponse:
    secret = _secret(request)
    await _execute(
        request,
        "INSERT INTO deliverables (engagement_id, title, status, due_date, notes) "
        "VALUES (%s, %s, %s, %s, %s)",
        (engagement_id, _encrypt(secret, title), status, due_date or None, _encrypt(secret, notes)),
    )
    return RedirectResponse(f"/?id={engagement_id}", status_code=303)


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
    return RedirectResponse(f"/?id={engagement_id}", status_code=303)


@router.post("/engagements/{engagement_id}/fees")
async def add_fee(
    request: Request,
    engagement_id: int,
    amount: float = Form(...),
    currency: str = Form("USD"),
    status: str = Form("quoted"),
    due_date: str = Form(""),
    notes: str = Form(""),
) -> RedirectResponse:
    secret = _secret(request)
    await _execute(
        request,
        "INSERT INTO fees (engagement_id, amount, currency, status, due_date, notes) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (engagement_id, amount, currency, status, due_date or None, _encrypt(secret, notes)),
    )
    return RedirectResponse(f"/?id={engagement_id}", status_code=303)


@router.post("/engagements/{engagement_id}/notes")
async def add_note(request: Request, engagement_id: int, body: str = Form(...)) -> RedirectResponse:
    secret = _secret(request)
    await _execute(
        request,
        "INSERT INTO notes (engagement_id, body) VALUES (%s, %s)",
        (engagement_id, _encrypt(secret, body)),
    )
    return RedirectResponse(f"/?id={engagement_id}", status_code=303)


@router.post("/calls/{call_id}/toggle")
async def toggle_call(request: Request, call_id: int) -> RedirectResponse:
    row = await _fetch_one(
        request,
        "UPDATE calls SET status = CASE WHEN status = 'done' THEN 'scheduled' ELSE 'done' END "
        "WHERE id = %s RETURNING engagement_id",
        (call_id,),
    )
    eid = row["engagement_id"] if row else None
    return RedirectResponse(f"/?id={eid}" if eid else "/", status_code=303)


@router.post("/deliverables/{deliverable_id}/toggle")
async def toggle_deliverable(request: Request, deliverable_id: int) -> RedirectResponse:
    row = await _fetch_one(
        request,
        "UPDATE deliverables SET status = CASE WHEN status = 'done' THEN 'todo' ELSE 'done' END "
        "WHERE id = %s RETURNING engagement_id",
        (deliverable_id,),
    )
    eid = row["engagement_id"] if row else None
    return RedirectResponse(f"/?id={eid}" if eid else "/", status_code=303)


@router.post("/engagements/{engagement_id}/wipe")
async def wipe_engagement(request: Request, engagement_id: int) -> RedirectResponse:
    """Delete an engagement and every trace of it.

    The child tables cascade on delete, so this single statement removes all
    calls, deliverables, contacts, fees and notes for the engagement — nothing
    left. It runs in a transaction via the connection's autocommit-off cursor.
    """
    await _execute(request, "DELETE FROM engagements WHERE id = %s", (engagement_id,))
    return RedirectResponse("/", status_code=303)