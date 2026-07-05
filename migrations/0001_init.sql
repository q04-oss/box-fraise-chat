-- box-fraise-chat schema
--
-- Signal-derived storage: the server distributes prekey bundles and
-- forwards ciphertext envelopes; it never sees plaintext.
--
-- Two roles (postgres owner, bf_chat runtime). FORCE ROW LEVEL
-- SECURITY on every table so RLS applies even when a connection
-- coincidentally has ownership.
--
-- No FK to users — box-fraise-chat has no users table. Identity is a
-- UUID matching box-fraise-server's user_id; the auth layer resolves
-- the token to that UUID before we ever hit these tables. If a user
-- is deleted upstream, cleanup is manual (rare) or via a periodic job.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Ensure the runtime role exists. On docker-compose it's created by
-- docker/init/01-roles.sql before migrations run; on Railway (which
-- has no init-scripts hook) this DO block creates it on the first
-- migration. Idempotent either way. The password is a placeholder —
-- Railway's managed Postgres doesn't hand the app an unrestricted
-- role, so bf_chat is currently unused in production and everything
-- goes through the postgres role. FORCE ROW LEVEL SECURITY below
-- makes that safe anyway.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bf_chat') THEN
    CREATE ROLE bf_chat WITH LOGIN PASSWORD 'bf_chat_dev';
  END IF;
END
$$;

-- ── Chat identity registration ─────────────────────────────────────
-- One row per user who has ever registered their crypto identity
-- with the chat service. identity_key is Curve25519 public in
-- Signal's DjB point format (33 bytes: 0x05 || X(32)).

CREATE TABLE chat_identities (
    user_id         UUID PRIMARY KEY,
    registration_id INTEGER NOT NULL CHECK (registration_id BETWEEN 1 AND 16383),
    identity_key    BYTEA   NOT NULL CHECK (octet_length(identity_key) = 33),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE chat_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_identities FORCE  ROW LEVEL SECURITY;

-- Anyone can read another user's identity — that's the point of a
-- public directory. A user can only write their own.
CREATE POLICY chat_identities_select ON chat_identities
    FOR SELECT USING (true);
CREATE POLICY chat_identities_write ON chat_identities
    FOR ALL USING (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

-- ── Signed prekey (rotated periodically by the client) ─────────────
-- 33-byte public + 64-byte XEd25519 signature by the identity key.
-- Verification is client-side when a bundle is fetched.

CREATE TABLE chat_signed_prekeys (
    user_id     UUID PRIMARY KEY REFERENCES chat_identities(user_id) ON DELETE CASCADE,
    key_id      INTEGER NOT NULL,
    public_key  BYTEA   NOT NULL CHECK (octet_length(public_key) = 33),
    signature   BYTEA   NOT NULL CHECK (octet_length(signature) = 64),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE chat_signed_prekeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_signed_prekeys FORCE  ROW LEVEL SECURITY;

CREATE POLICY chat_signed_prekeys_select ON chat_signed_prekeys
    FOR SELECT USING (true);
CREATE POLICY chat_signed_prekeys_write ON chat_signed_prekeys
    FOR ALL USING (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid);

-- ── One-time prekeys (consumed on bundle fetch) ────────────────────
-- Ephemeral keys. Each is used at most once; consumed_at marks it
-- spent. Bundle-fetch selects one unconsumed row for the recipient,
-- marks it consumed, and returns it.

CREATE TABLE chat_one_time_prekeys (
    user_id     UUID    NOT NULL REFERENCES chat_identities(user_id) ON DELETE CASCADE,
    key_id      INTEGER NOT NULL,
    public_key  BYTEA   NOT NULL CHECK (octet_length(public_key) = 33),
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key_id)
);

CREATE INDEX chat_one_time_prekeys_available_idx
    ON chat_one_time_prekeys(user_id)
    WHERE consumed_at IS NULL;

ALTER TABLE chat_one_time_prekeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_one_time_prekeys FORCE  ROW LEVEL SECURITY;

-- Owner writes; anyone can consume via the service function that
-- runs under admin context. Direct SELECT is scoped to the owner
-- (nobody but the owner should enumerate their unspent prekeys —
-- distribution is one-at-a-time via the bundle-fetch endpoint).
CREATE POLICY chat_one_time_prekeys_owner ON chat_one_time_prekeys
    FOR ALL USING (user_id = NULLIF(current_setting('app.user_id', true), '')::uuid);
CREATE POLICY chat_one_time_prekeys_admin ON chat_one_time_prekeys
    FOR ALL USING (current_setting('app.is_admin', true) = 'true');

-- ── Message queue ──────────────────────────────────────────────────
-- One row per envelope in flight. The server stores opaque ciphertext
-- (envelope_type + bytes) plus routing metadata. Delivered messages
-- are marked; acknowledged messages are hard-deleted by the client's
-- DELETE call (or by a background reaper after a retention window).
--
-- envelope_type mirrors Signal's Envelope.Type enum:
--   1 = CIPHERTEXT (whisper), 3 = PREKEY_BUNDLE (initial X3DH).

CREATE TABLE chat_messages (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_user_id    UUID NOT NULL,
    recipient_user_id UUID NOT NULL,
    envelope_type     SMALLINT NOT NULL CHECK (envelope_type IN (1, 3)),
    ciphertext        BYTEA    NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 65536),
    received_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at      TIMESTAMPTZ,
    acknowledged_at   TIMESTAMPTZ
);

CREATE INDEX chat_messages_recipient_pending_idx
    ON chat_messages(recipient_user_id, received_at)
    WHERE acknowledged_at IS NULL;

ALTER TABLE chat_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE chat_messages FORCE  ROW LEVEL SECURITY;

-- Recipient can read + delete their own inbox.
-- Sender can write to any recipient (fan-in from user context).
CREATE POLICY chat_messages_read ON chat_messages
    FOR SELECT USING (
        recipient_user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
    );
CREATE POLICY chat_messages_ack ON chat_messages
    FOR UPDATE USING (
        recipient_user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
    );
CREATE POLICY chat_messages_delete ON chat_messages
    FOR DELETE USING (
        recipient_user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
    );
CREATE POLICY chat_messages_send ON chat_messages
    FOR INSERT WITH CHECK (
        sender_user_id = NULLIF(current_setting('app.user_id', true), '')::uuid
    );

-- ── bf_chat grants ─────────────────────────────────────────────────
-- Narrow verbs only. No UPDATE on identities/prekeys except what the
-- app uses; no TRUNCATE; no schema mutation.

GRANT USAGE ON SCHEMA public TO bf_chat;

GRANT SELECT, INSERT, UPDATE ON chat_identities       TO bf_chat;
GRANT SELECT, INSERT, UPDATE, DELETE ON chat_signed_prekeys  TO bf_chat;
GRANT SELECT, INSERT, UPDATE, DELETE ON chat_one_time_prekeys TO bf_chat;
GRANT SELECT, INSERT, UPDATE, DELETE ON chat_messages         TO bf_chat;

COMMIT;
