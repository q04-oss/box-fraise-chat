-- Runtime role. Matches the two-role pattern from box-fraise-server:
-- postgres owns everything, bf_chat is the app connection with only
-- the verbs it needs. No BYPASSRLS.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bf_chat') THEN
    CREATE ROLE bf_chat WITH LOGIN PASSWORD 'bf_chat_dev';
  END IF;
END
$$;

GRANT CONNECT ON DATABASE fraise_chat TO bf_chat;
