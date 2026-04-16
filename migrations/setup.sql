CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS compliance_event (
    event_id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    event_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_compliance_event_occurred_at ON compliance_event (occurred_at);
CREATE INDEX IF NOT EXISTS ix_compliance_event_event_hash ON compliance_event (event_hash);

CREATE TABLE IF NOT EXISTS hourly_root (
    hour_start TIMESTAMPTZ PRIMARY KEY,
    root_hash BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    tsa_proof BYTEA,
    signed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_hourly_root_signed_at ON hourly_root (signed_at);

-- REQ-1.1: Kernel-Level Append-Only Storage
-- Prevents any modification or deletion of compliance logs

CREATE OR REPLACE FUNCTION block_immutable_change()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'REQ-1.1 Violation: Table is append-only. UPDATE/DELETE/TRUNCATE denied.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tr_compliance_event_immutability ON compliance_event;
CREATE TRIGGER tr_compliance_event_immutability
BEFORE UPDATE OR DELETE OR TRUNCATE ON compliance_event
FOR EACH STATEMENT EXECUTE FUNCTION block_immutable_change();

DROP TRIGGER IF EXISTS tr_hourly_root_immutability ON hourly_root;
CREATE TRIGGER tr_hourly_root_immutability
BEFORE UPDATE OR DELETE OR TRUNCATE ON hourly_root
FOR EACH STATEMENT EXECUTE FUNCTION block_immutable_change();

-- REQ-1.1: Aggressive rejection using Rules
CREATE RULE rule_compliance_event_no_update AS ON UPDATE TO compliance_event DO INSTEAD NOTHING;
CREATE RULE rule_compliance_event_no_delete AS ON DELETE TO compliance_event DO INSTEAD NOTHING;
CREATE RULE rule_hourly_root_no_update AS ON UPDATE TO hourly_root DO INSTEAD NOTHING;
CREATE RULE rule_hourly_root_no_delete AS ON DELETE TO hourly_root DO INSTEAD NOTHING;
