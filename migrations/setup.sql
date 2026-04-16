CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS ltree;
CREATE EXTENSION IF NOT EXISTS btree_gist;

-- =============================================
-- BASE LAYER (Merkle & Events)
-- =============================================

CREATE TABLE IF NOT EXISTS compliance_event (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
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

-- =============================================
-- REGULATORY LAYER (DDL harmonization)
-- =============================================

CREATE TYPE tipo_norma AS ENUM (
  'LEGGE', 'DECRETO_LEGISLATIVO', 'DPR', 'DPCM',
  'REGOLAMENTO_UE', 'DIRETTIVA_UE', 'CIRCOLARE', 'DELIBERA'
);

CREATE TYPE tipo_unita AS ENUM (
  'ARTICOLO', 'COMMA', 'LETTERA', 'NUMERO', 'ALLEGATO', 'SEZIONE'
);

CREATE TABLE norma (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  codice      TEXT UNIQUE NOT NULL,
  tipo        tipo_norma NOT NULL,
  titolo      TEXT NOT NULL,
  numero      TEXT,
  anno        SMALLINT,
  gu_serie    TEXT,
  ente        TEXT,
  vigenza     daterange NOT NULL DEFAULT daterange(CURRENT_DATE, NULL),
  metadati    JSONB DEFAULT '{}',
  path        ltree UNIQUE
);

CREATE TABLE unita_normativa (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  norma_id    UUID NOT NULL REFERENCES norma(id),
  parent_id   UUID REFERENCES unita_normativa(id),
  tipo        tipo_unita NOT NULL,
  numero      TEXT,
  rubrica     TEXT,
  contenuto   TEXT,
  path        ltree UNIQUE NOT NULL,
  vigenza     daterange,
  versione    SMALLINT DEFAULT 1,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TYPE tipo_relazione AS ENUM (
  'RIMANDA_A', 'ABROGA', 'MODIFICA', 'INTEGRA', 'RECEPISCE', 'ATTUA', 'DEROGA', 'INTERPRETA', 'SOSPENDE'
);

CREATE TABLE relazione_normativa (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  da_unita_id   UUID NOT NULL REFERENCES unita_normativa(id),
  a_unita_id    UUID NOT NULL REFERENCES unita_normativa(id),
  tipo          tipo_relazione NOT NULL,
  descrizione   TEXT,
  vigenza       daterange,
  bidirezionale BOOLEAN DEFAULT FALSE,
  peso          NUMERIC(4,3) DEFAULT 1.0,
  metadati      JSONB DEFAULT '{}',
  CHECK (da_unita_id <> a_unita_id)
);

CREATE TYPE tipo_obbligo AS ENUM (
  'DICHIARAZIONE', 'PAGAMENTO', 'COMUNICAZIONE', 'AUTORIZZAZIONE', 'REGISTRAZIONE', 'CONSERVAZIONE'
);

CREATE TABLE obbligo (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  unita_normativa_id    UUID REFERENCES unita_normativa(id),
  codice                TEXT,
  descrizione           TEXT NOT NULL,
  tipo                  tipo_obbligo,
  frequenza             TEXT,
  scadenza_testo        TEXT,
  sanzione              TEXT,
  vigenza               daterange
);

CREATE TABLE soggetto (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tipo        TEXT NOT NULL,
  categoria   TEXT,
  descrizione TEXT
);

CREATE TABLE obbligo_soggetto (
  obbligo_id  UUID REFERENCES obbligo(id),
  soggetto_id UUID REFERENCES soggetto(id),
  ruolo       TEXT NOT NULL,
  PRIMARY KEY (obbligo_id, soggetto_id, ruolo)
);

-- Indexes
CREATE INDEX idx_unita_path ON unita_normativa USING GIST (path);
CREATE INDEX idx_norma_path  ON norma          USING GIST (path);
CREATE INDEX idx_unita_vigenza   ON unita_normativa   USING GIST (vigenza);
CREATE INDEX idx_relazione_vigenza ON relazione_normativa USING GIST (vigenza);
CREATE INDEX idx_rel_da ON relazione_normativa (da_unita_id, tipo);
CREATE INDEX idx_rel_a  ON relazione_normativa (a_unita_id,  tipo);

-- =============================================
-- REQ-1.1: Kernel-Level Append-Only Storage
-- =============================================

CREATE OR REPLACE FUNCTION block_immutable_change()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'REQ-1.1 Violation: Table is append-only. UPDATE/DELETE/TRUNCATE denied.';
END;
$$ LANGUAGE plpgsql;

-- Applied to ALL tables
DO $$
DECLARE
    t text;
BEGIN
    FOR t IN (SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE') LOOP
        EXECUTE format('CREATE TRIGGER tr_%I_immutability BEFORE UPDATE OR DELETE OR TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION block_immutable_change()', t, t);
        EXECUTE format('CREATE RULE rule_%I_no_update AS ON UPDATE TO %I DO INSTEAD NOTHING', t, t);
        EXECUTE format('CREATE RULE rule_%I_no_delete AS ON DELETE TO %I DO INSTEAD NOTHING', t, t);
    END LOOP;
END;
$$;
