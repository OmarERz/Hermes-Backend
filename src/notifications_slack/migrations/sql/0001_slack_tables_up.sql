-- Tables of the Slack module (NOT-07, D-085; proposal docs/datos/propuestas/slack-tables.md, approved 23 Nov 2026).
-- Owned by migrator (DAT-05); only slack_module may use them. No foreign keys to the backend's tables on purpose:
-- the module knows only the contract, and contract event ids are text.

CREATE TABLE slack_thread (
  thread_key text NOT NULL,
  audience text NOT NULL,
  channel_id text NOT NULL,
  root_ts text NOT NULL,
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CONSTRAINT slack_thread_pkey PRIMARY KEY (thread_key, audience),
  CONSTRAINT slack_thread_key_check CHECK (thread_key ~ '^[0-9a-f]{64}$'),
  CONSTRAINT slack_thread_audience_check CHECK (audience IN ('standard', 'restricted')),
  CONSTRAINT slack_thread_channel_check CHECK (channel_id ~ '^[A-Z0-9]{2,32}$'),
  CONSTRAINT slack_thread_ts_check CHECK (root_ts ~ '^[0-9]{1,12}\.[0-9]{1,9}$'),
  CONSTRAINT slack_thread_dates_check CHECK (updated_at >= created_at)
);

CREATE TABLE slack_delivery (
  event_id text NOT NULL,
  audience text NOT NULL,
  channel_id text NOT NULL,
  delivery text NOT NULL,
  message_ts text NOT NULL,
  delivered_at timestamptz NOT NULL,
  CONSTRAINT slack_delivery_pkey PRIMARY KEY (event_id, audience),
  CONSTRAINT slack_delivery_event_check CHECK (char_length(event_id) BETWEEN 1 AND 128),
  CONSTRAINT slack_delivery_audience_check CHECK (audience IN ('standard', 'restricted')),
  CONSTRAINT slack_delivery_channel_check CHECK (channel_id ~ '^[A-Z0-9]{2,32}$'),
  CONSTRAINT slack_delivery_kind_check CHECK (delivery IN ('message', 'reply', 'digest')),
  CONSTRAINT slack_delivery_ts_check CHECK (message_ts ~ '^[0-9]{1,12}\.[0-9]{1,9}$')
);
CREATE INDEX slack_delivery_delivered_at_idx ON slack_delivery (delivered_at);

CREATE TABLE slack_digest_item (
  event_id text NOT NULL,
  channel_id text NOT NULL,
  payload jsonb NOT NULL,
  queued_at timestamptz NOT NULL,
  status text NOT NULL,
  attempts smallint NOT NULL DEFAULT 0,
  next_attempt_at timestamptz,
  last_error text,
  digest_ts text,
  CONSTRAINT slack_digest_item_pkey PRIMARY KEY (event_id),
  CONSTRAINT slack_digest_item_event_check CHECK (char_length(event_id) BETWEEN 1 AND 128),
  CONSTRAINT slack_digest_item_channel_check CHECK (channel_id ~ '^[A-Z0-9]{2,32}$'),
  CONSTRAINT slack_digest_item_payload_check CHECK (jsonb_typeof(payload) = 'object'),
  CONSTRAINT slack_digest_item_status_check CHECK (status IN ('queued', 'failed')),
  CONSTRAINT slack_digest_item_attempts_check CHECK (attempts >= 0),
  CONSTRAINT slack_digest_item_next_check CHECK ((status = 'queued') = (next_attempt_at IS NOT NULL)),
  CONSTRAINT slack_digest_item_error_check CHECK (char_length(last_error) <= 200),
  CONSTRAINT slack_digest_item_ts_check CHECK (digest_ts ~ '^[0-9]{1,12}\.[0-9]{1,9}$')
);
CREATE INDEX slack_digest_item_due_idx ON slack_digest_item (channel_id, next_attempt_at) WHERE status = 'queued';

-- slack_module: its own tables only (model v1 §17). Nothing else is granted, and nothing on slack_alembic_version.
REVOKE ALL ON slack_thread, slack_delivery, slack_digest_item FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON slack_thread, slack_delivery, slack_digest_item TO slack_module;
