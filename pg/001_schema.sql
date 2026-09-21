-- clear-amber-heron — engagement manager schema.
--
-- Cook applies every pg/*.sql in filename order before the container is
-- deployed, so the app boots into a database that already has its tables.
-- Keep it re-runnable: a build may be redeployed, and a half-applied migration
-- on something that disappears within 24 hours is not worth a migration
-- framework.
--
-- Encryption note: the sensitive free-text fields below (names, clients,
-- notes, deliverable titles, contact details) are stored as ciphertext. The
-- application encrypts them with an authenticated stream cipher before they
-- are written, so the columns here are TEXT holding base64 blobs, not
-- plaintext. That is why no seed rows are inserted in SQL: a row written here
-- would be plaintext the app could never decrypt. Instead the app seeds a few
-- realistic engagements on first load, through its own encrypt-on-write path.
--
-- Wipe note: every child table references engagements with
-- ON DELETE CASCADE, so deleting one engagement row removes every call,
-- deliverable, contact, fee and note that belonged to it — nothing left.

CREATE TABLE IF NOT EXISTS engagements (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,          -- encrypted
    kind        TEXT NOT NULL,          -- advising | board | consulting
    client      TEXT NOT NULL,          -- encrypted
    status      TEXT NOT NULL DEFAULT 'active',  -- active | on_hold | ended
    start_date  DATE,
    end_date    DATE,
    notes       TEXT,                   -- encrypted
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS calls (
    id            SERIAL PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,        -- recurring | adhoc | board
    title         TEXT NOT NULL,        -- encrypted
    frequency     TEXT,                 -- weekly | monthly | quarterly (recurring/board)
    next_due      DATE,
    status        TEXT NOT NULL DEFAULT 'scheduled',  -- scheduled | done | cancelled
    notes         TEXT,                 -- encrypted
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS deliverables (
    id            SERIAL PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,        -- encrypted
    status        TEXT NOT NULL DEFAULT 'todo',  -- todo | in_progress | done
    due_date      DATE,
    notes         TEXT,                 -- encrypted
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS contacts (
    id            SERIAL PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,        -- encrypted
    role          TEXT,                 -- encrypted
    email         TEXT,                 -- encrypted
    phone         TEXT,                 -- encrypted
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fees (
    id            SERIAL PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    amount        NUMERIC(12,2) NOT NULL,
    currency      TEXT NOT NULL DEFAULT 'USD',
    status        TEXT NOT NULL DEFAULT 'quoted',  -- quoted | invoiced | paid
    due_date      DATE,
    notes         TEXT,                 -- encrypted
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS notes (
    id            SERIAL PRIMARY KEY,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    body          TEXT NOT NULL,        -- encrypted
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);