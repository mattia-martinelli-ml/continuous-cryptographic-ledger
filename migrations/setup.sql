CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS compliance_event (
    event_id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    event_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_compliance_event_occurred_at ON compliance_event (occurred_at);
CREATE INDEX IF NOT EXISTS ix_compliance_event_event_hash ON compliance_event (event_hash);

CREATE TABLE IF NOT EXISTS hourly_root (
    hour_start TIMESTAMPTZ PRIMARY KEY,
    root_hash BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    signed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_hourly_root_signed_at ON hourly_root (signed_at);
