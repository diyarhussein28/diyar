-- migrate:up
-- =============================================================================
-- ParkShield — PostgreSQL 16 schema (SRS v2)
-- Conventions
--   * All PKs are UUID v7-compatible (generated in app; gen_random_uuid() fallback).
--   * Columns ending in _enc   = AES-256-GCM ciphertext (envelope, app-level). bytea.
--   * Columns ending in _bidx  = HMAC-SHA256 blind index for equality lookup. bytea.
--   * Columns ending in _hash  = SHA-256 of a secret (tokens). Never store the raw secret.
--   * key_version              = which data-encryption key encrypted the row (rotation).
--   * Soft delete is NOT used for personal data: GDPR erasure = hard delete / anonymise.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- ---------------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------------
CREATE TYPE user_role          AS ENUM ('customer', 'support', 'admin', 'superadmin');
CREATE TYPE user_status        AS ENUM ('active', 'suspended', 'pending_deletion');
CREATE TYPE ui_lang            AS ENUM ('de', 'en');
CREATE TYPE channel_type       AS ENUM ('webpush', 'email', 'whatsapp', 'sms', 'voice', 'telegram');
CREATE TYPE token_status       AS ENUM ('generated', 'printed', 'shipped', 'active', 'revoked');
CREATE TYPE consent_state      AS ENUM ('pending', 'confirmed', 'declined', 'revoked');
CREATE TYPE alert_severity     AS ENUM ('info', 'normal', 'urgent');
CREATE TYPE alert_status       AS ENUM ('created', 'blocked', 'dispatched', 'delivered',
                                        'acknowledged', 'escalated', 'expired');
CREATE TYPE delivery_status    AS ENUM ('queued', 'sent', 'delivered', 'read', 'failed', 'skipped');
CREATE TYPE recipient_kind     AS ENUM ('owner', 'emergency_contact', 'org_member');
CREATE TYPE moderation_state   AS ENUM ('not_required', 'passed', 'blocked', 'review');
CREATE TYPE plan_code          AS ENUM ('plus', 'premium', 'business');
CREATE TYPE subscription_state AS ENUM ('incomplete', 'active', 'past_due', 'canceled', 'expired');
CREATE TYPE billing_interval   AS ENUM ('month', 'year');
CREATE TYPE org_role           AS ENUM ('owner', 'manager', 'driver');
CREATE TYPE decal_product      AS ENUM ('a6_dashboard_card', 'uv_vinyl_sticker', 'nfc_vinyl_sticker');
CREATE TYPE order_status       AS ENUM ('pending_payment', 'paid', 'in_production', 'shipped',
                                        'delivered', 'canceled', 'refunded');
CREATE TYPE ticket_status      AS ENUM ('open', 'in_progress', 'waiting_customer', 'resolved', 'closed');
CREATE TYPE ticket_channel     AS ENUM ('in_app', 'email', 'whatsapp', 'ai_bot');
CREATE TYPE dsr_type           AS ENUM ('access_export', 'erasure', 'rectification', 'restriction');
CREATE TYPE dsr_status         AS ENUM ('received', 'in_progress', 'completed', 'rejected');
CREATE TYPE abuse_status       AS ENUM ('open', 'actioned', 'dismissed');
CREATE TYPE chat_sender        AS ENUM ('scanner', 'owner', 'system');

-- ---------------------------------------------------------------------------
-- Identity & access
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email              citext      NOT NULL UNIQUE,
    email_verified_at  timestamptz,
    display_name       varchar(80),
    preferred_lang     ui_lang     NOT NULL DEFAULT 'de',
    timezone           varchar(64) NOT NULL DEFAULT 'Europe/Berlin',
    role               user_role   NOT NULL DEFAULT 'customer',
    status             user_status NOT NULL DEFAULT 'active',
    stripe_customer_id varchar(64) UNIQUE,
    last_login_at      timestamptz,
    deletion_due_at    timestamptz,               -- set when erasure requested (grace 24h)
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

-- Passkeys (WebAuthn). Magic-link is the fallback; no passwords are stored.
CREATE TABLE webauthn_credentials (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id  bytea       NOT NULL UNIQUE,
    public_key     bytea       NOT NULL,
    sign_count     bigint      NOT NULL DEFAULT 0,
    transports     text[],
    label          varchar(60),
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_used_at   timestamptz
);

CREATE TABLE magic_link_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  bytea       NOT NULL UNIQUE,
    expires_at  timestamptz NOT NULL,             -- 15 minutes
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    bytea       NOT NULL UNIQUE,
    user_agent    varchar(255),
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

-- ---------------------------------------------------------------------------
-- Organisations (Business / Fleet plan)
-- ---------------------------------------------------------------------------
CREATE TABLE organizations (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name               varchar(120) NOT NULL,
    vat_id             varchar(20),                -- USt-IdNr. for B2B invoices
    billing_email      citext       NOT NULL,
    stripe_customer_id varchar(64)  UNIQUE,
    created_at         timestamptz  NOT NULL DEFAULT now(),
    updated_at         timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE organization_members (
    organization_id uuid     NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         uuid     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            org_role NOT NULL DEFAULT 'driver',
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);

-- ---------------------------------------------------------------------------
-- Contact channels (where the OWNER receives alerts)
-- ---------------------------------------------------------------------------
CREATE TABLE contact_channels (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type           channel_type NOT NULL,
    address_enc    bytea,                          -- phone / chat id; NULL for webpush & email (email lives on users)
    address_bidx   bytea,                          -- dedupe + inbound webhook lookup
    key_version    smallint     NOT NULL DEFAULT 1,
    priority       smallint     NOT NULL DEFAULT 1, -- 1 = tried first
    verified_at    timestamptz,                     -- OTP-verified; unverified channels are never used
    opted_in_at    timestamptz,                     -- WhatsApp/SMS explicit opt-in (Meta + UWG §7)
    is_enabled     boolean      NOT NULL DEFAULT true,
    created_at     timestamptz  NOT NULL DEFAULT now(),
    UNIQUE (user_id, type, address_bidx)
);
CREATE INDEX contact_channels_bidx ON contact_channels(address_bidx);

CREATE TABLE push_subscriptions (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint     text        NOT NULL UNIQUE,
    p256dh       text        NOT NULL,
    auth         text        NOT NULL,
    device_label varchar(60),
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_ok_at   timestamptz,
    failed_count smallint    NOT NULL DEFAULT 0     -- auto-removed after 410 Gone / 5 failures
);

-- ---------------------------------------------------------------------------
-- Vehicles & QR tokens
-- ---------------------------------------------------------------------------
CREATE TABLE vehicles (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id    uuid REFERENCES users(id) ON DELETE CASCADE,
    organization_id  uuid REFERENCES organizations(id) ON DELETE CASCADE,
    nickname         varchar(60) NOT NULL,
    plate_enc        bytea,                         -- license plate = personal data
    plate_bidx       bytea,
    key_version      smallint    NOT NULL DEFAULT 1,
    make_model       varchar(80),
    color            varchar(30),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT vehicle_has_owner CHECK (owner_user_id IS NOT NULL OR organization_id IS NOT NULL)
);
CREATE INDEX vehicles_owner_idx ON vehicles(owner_user_id);
CREATE INDEX vehicles_org_idx   ON vehicles(organization_id);

-- The public code printed in the QR (e.g. https://pkshd.de/s/K7QX4M2R9T) is
-- 10 chars Crockford-Base32 = 50 bits random. Only its SHA-256 is stored, so a DB
-- leak cannot be used to forge scans. A vehicle can have several tokens over time
-- (rotation after leak / reprint); exactly one should be active per decal.
CREATE TABLE qr_tokens (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    vehicle_id         uuid         REFERENCES vehicles(id) ON DELETE CASCADE,  -- NULL = pre-printed stock, not yet claimed
    code_hash          bytea        NOT NULL UNIQUE,
    code_hint          char(4)      NOT NULL,       -- last 4 chars, for support lookups only
    status             token_status NOT NULL DEFAULT 'generated',
    cta_header         varchar(40)  NOT NULL DEFAULT 'Kontaktieren Sie mich',
    design_template_id varchar(40)  NOT NULL DEFAULT 'classic',
    batch_id           uuid,                         -- admin batch generation
    activated_at       timestamptz,
    revoked_at         timestamptz,
    revoke_reason      varchar(120),
    created_at         timestamptz  NOT NULL DEFAULT now()
);
CREATE INDEX qr_tokens_vehicle_idx ON qr_tokens(vehicle_id);

-- Secondary contact for escalation. Must CONFIRM via link before use (Art. 6/7 GDPR).
CREATE TABLE emergency_contacts (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             uuid          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vehicle_id          uuid          REFERENCES vehicles(id) ON DELETE CASCADE, -- NULL = all vehicles
    display_name        varchar(60)   NOT NULL,
    channel             channel_type  NOT NULL,
    address_enc         bytea         NOT NULL,
    address_bidx        bytea         NOT NULL,
    key_version         smallint      NOT NULL DEFAULT 1,
    escalation_order    smallint      NOT NULL DEFAULT 1,
    consent             consent_state NOT NULL DEFAULT 'pending',
    consent_token_hash  bytea         UNIQUE,
    consent_requested_at timestamptz  NOT NULL DEFAULT now(),
    consent_decided_at  timestamptz,
    created_at          timestamptz   NOT NULL DEFAULT now()
);
CREATE INDEX emergency_contacts_user_idx ON emergency_contacts(user_id);

-- Quiet hours / schedule. Urgent alerts bypass when urgent_override = true.
CREATE TABLE notification_rules (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vehicle_id      uuid     REFERENCES vehicles(id) ON DELETE CASCADE,
    quiet_start     time     NOT NULL,              -- local time in users.timezone
    quiet_end       time     NOT NULL,
    days_mask       smallint NOT NULL DEFAULT 127,  -- bit0 = Monday … bit6 = Sunday
    urgent_override boolean  NOT NULL DEFAULT true,
    escalation_minutes smallint NOT NULL DEFAULT 7 CHECK (escalation_minutes BETWEEN 3 AND 30),
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Alerts
-- ---------------------------------------------------------------------------
CREATE TABLE alert_types (
    code                     varchar(32)    PRIMARY KEY,
    severity                 alert_severity NOT NULL,
    escalates                boolean        NOT NULL DEFAULT false,
    label_de                 varchar(80)    NOT NULL,
    label_en                 varchar(80)    NOT NULL,
    sort_order               smallint       NOT NULL,
    is_active                boolean        NOT NULL DEFAULT true
);

INSERT INTO alert_types (code, severity, escalates, label_de, label_en, sort_order) VALUES
 ('blocking',     'urgent', true,  'Fahrzeug versperrt Ausfahrt',        'Vehicle is blocking a driveway', 1),
 ('lights_on',    'normal', false, 'Licht brennt noch',                  'Lights are still on',            2),
 ('window_open',  'normal', true,  'Fenster / Schiebedach offen',        'Window or sunroof open',         3),
 ('damage',       'urgent', true,  'Beschädigung / Parkschaden entdeckt','Damage / parking collision',     4),
 ('alarm',        'normal', false, 'Alarmanlage ausgelöst',              'Alarm is going off',             5),
 ('towing_risk',  'urgent', true,  'Abschleppen droht',                  'Vehicle is about to be towed',   6),
 ('custom',       'normal', false, 'Eigene Nachricht',                   'Custom message',                 7);

CREATE TABLE alerts (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    qr_token_id           uuid             NOT NULL REFERENCES qr_tokens(id) ON DELETE CASCADE,
    vehicle_id            uuid             NOT NULL REFERENCES vehicles(id) ON DELETE CASCADE,
    alert_type            varchar(32)      NOT NULL REFERENCES alert_types(code),
    severity              alert_severity   NOT NULL,
    status                alert_status     NOT NULL DEFAULT 'created',
    custom_message_enc    bytea,                     -- purged after 7 days
    key_version           smallint         NOT NULL DEFAULT 1,
    moderation            moderation_state NOT NULL DEFAULT 'not_required',
    scanner_lang          ui_lang          NOT NULL DEFAULT 'de',
    -- Pseudonymous scanner reference: HMAC(daily_salt, ip_prefix|ua|token).
    -- Daily salt is destroyed after 24h -> value becomes unlinkable. Column nulled after 24h.
    scanner_ref           bytea,
    status_view_hash      bytea            NOT NULL, -- secret the scanner's browser holds to poll status
    ack_token_hash        bytea            UNIQUE,   -- single-use link in the owner notification
    ack_token_expires_at  timestamptz,
    escalate_at           timestamptz,               -- NULL = no escalation
    dispatched_at         timestamptz,
    acknowledged_at       timestamptz,
    escalated_at          timestamptz,
    expires_at            timestamptz      NOT NULL DEFAULT now() + interval '2 hours',
    created_at            timestamptz      NOT NULL DEFAULT now()
);
CREATE INDEX alerts_vehicle_created_idx ON alerts(vehicle_id, created_at DESC);
CREATE INDEX alerts_escalation_due_idx  ON alerts(escalate_at)
    WHERE status IN ('dispatched', 'delivered') AND escalate_at IS NOT NULL;
CREATE INDEX alerts_scanner_ref_idx     ON alerts(scanner_ref) WHERE scanner_ref IS NOT NULL;

CREATE TABLE alert_deliveries (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id            uuid            NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    recipient           recipient_kind  NOT NULL,
    emergency_contact_id uuid           REFERENCES emergency_contacts(id) ON DELETE SET NULL,
    channel             channel_type    NOT NULL,
    provider            varchar(30)     NOT NULL,   -- 'webpush','brevo','360dialog','twilio','seven'
    provider_message_id varchar(128),
    status              delivery_status NOT NULL DEFAULT 'queued',
    attempt             smallint        NOT NULL DEFAULT 1,
    error_code          varchar(64),
    cost_micros_eur     integer,                     -- for unit-economics reporting
    queued_at           timestamptz     NOT NULL DEFAULT now(),
    sent_at             timestamptz,
    delivered_at        timestamptz,
    read_at             timestamptz
);
CREATE INDEX alert_deliveries_alert_idx ON alert_deliveries(alert_id);
CREATE INDEX alert_deliveries_provider_msg_idx ON alert_deliveries(provider, provider_message_id);

-- Two-way anonymous chat (Premium). Content purged 7 days after alert closes.
CREATE TABLE alert_messages (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id    uuid             NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    sender      chat_sender      NOT NULL,
    body_enc    bytea            NOT NULL,
    key_version smallint         NOT NULL DEFAULT 1,
    moderation  moderation_state NOT NULL DEFAULT 'passed',
    created_at  timestamptz      NOT NULL DEFAULT now()
);
CREATE INDEX alert_messages_alert_idx ON alert_messages(alert_id, created_at);

-- Owner reports a malicious scan -> scanner_ref blocked for that token (and globally if repeated).
CREATE TABLE abuse_reports (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id      uuid         NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    reported_by   uuid         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason        varchar(40)  NOT NULL,
    note          varchar(500),
    status        abuse_status NOT NULL DEFAULT 'open',
    handled_by    uuid         REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz  NOT NULL DEFAULT now(),
    handled_at    timestamptz
);

CREATE TABLE scanner_blocks (
    scanner_ref  bytea       NOT NULL,
    qr_token_id  uuid        REFERENCES qr_tokens(id) ON DELETE CASCADE,  -- NULL = global
    reason       varchar(40) NOT NULL,
    expires_at   timestamptz NOT NULL,             -- max 30 days
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scanner_blocks_ref_idx ON scanner_blocks(scanner_ref, expires_at);

-- ---------------------------------------------------------------------------
-- Plans, subscriptions & fair-use metering
-- ---------------------------------------------------------------------------
CREATE TABLE plans (
    code                  plan_code    PRIMARY KEY,
    name                  varchar(40)  NOT NULL,
    price_year_gross_cents integer     NOT NULL,     -- incl. 19 % VAT (B2C) / net for business
    price_month_gross_cents integer,
    per_vehicle           boolean      NOT NULL DEFAULT false,
    limits                jsonb        NOT NULL,     -- {"vehicles":2,"whatsapp_per_month":30,...}
    is_public             boolean      NOT NULL DEFAULT true
);

INSERT INTO plans (code, name, price_year_gross_cents, price_month_gross_cents, per_vehicle, limits) VALUES
 ('plus',     'ParkShield Plus',     2900, 299, false,
   '{"vehicles":2,"emergency_contacts":1,"whatsapp_per_month":30,"sms_per_month":0,"voice_minutes_per_month":0,"chat":false,"parking_assistant":true,"decals_included_per_year":1}'),
 ('premium',  'ParkShield Premium',  5900, 599, false,
   '{"vehicles":5,"emergency_contacts":3,"whatsapp_per_month":100,"sms_per_month":15,"voice_minutes_per_month":20,"chat":true,"parking_assistant":true,"decals_included_per_year":3}'),
 ('business', 'ParkShield Business', 3900, NULL, true,
   '{"vehicles_min":5,"emergency_contacts":5,"whatsapp_per_vehicle_month":50,"sms_per_vehicle_month":10,"voice_minutes_per_vehicle_month":10,"chat":true,"api":true,"sso":false,"decals_included_per_year":1}');

CREATE TABLE subscriptions (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                uuid               REFERENCES users(id) ON DELETE CASCADE,
    organization_id        uuid               REFERENCES organizations(id) ON DELETE CASCADE,
    plan                   plan_code          NOT NULL REFERENCES plans(code),
    interval               billing_interval   NOT NULL DEFAULT 'year',
    quantity               integer            NOT NULL DEFAULT 1,   -- vehicles for business
    status                 subscription_state NOT NULL,
    stripe_subscription_id varchar(64)        UNIQUE,
    withdrawal_waiver_at   timestamptz,                -- consumer asked for immediate start (§356(4) BGB / §357a Wertersatz)
    current_period_end     timestamptz,
    cancel_at_period_end   boolean            NOT NULL DEFAULT false,
    canceled_at            timestamptz,                -- §312k BGB "Kündigungsbutton" timestamp
    created_at             timestamptz        NOT NULL DEFAULT now(),
    updated_at             timestamptz        NOT NULL DEFAULT now(),
    CONSTRAINT subscription_has_subject CHECK (user_id IS NOT NULL OR organization_id IS NOT NULL)
);
CREATE UNIQUE INDEX subscriptions_one_live_per_user ON subscriptions(user_id)
    WHERE status IN ('active', 'past_due') AND user_id IS NOT NULL;
CREATE UNIQUE INDEX subscriptions_one_live_per_org ON subscriptions(organization_id)
    WHERE status IN ('active', 'past_due') AND organization_id IS NOT NULL;

CREATE TABLE usage_counters (
    subject_id  uuid        NOT NULL,              -- user or organization id
    period      date        NOT NULL,              -- first day of month
    metric      varchar(32) NOT NULL,              -- 'whatsapp','sms','voice_seconds','alerts_received'
    value       integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (subject_id, period, metric)
);

-- ---------------------------------------------------------------------------
-- Decal shop
-- ---------------------------------------------------------------------------
CREATE TABLE decal_orders (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               uuid         REFERENCES users(id) ON DELETE SET NULL,
    organization_id       uuid         REFERENCES organizations(id) ON DELETE SET NULL,
    status                order_status NOT NULL DEFAULT 'pending_payment',
    shipping_address_enc  bytea        NOT NULL,     -- purged 90 days after delivery
    key_version           smallint     NOT NULL DEFAULT 1,
    total_gross_cents     integer      NOT NULL,
    included_in_plan      boolean      NOT NULL DEFAULT false,
    stripe_payment_intent varchar(64)  UNIQUE,
    print_partner_ref     varchar(64),
    tracking_number       varchar(64),
    created_at            timestamptz  NOT NULL DEFAULT now(),
    shipped_at            timestamptz,
    delivered_at          timestamptz
);

CREATE TABLE decal_order_items (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id     uuid          NOT NULL REFERENCES decal_orders(id) ON DELETE CASCADE,
    qr_token_id  uuid          NOT NULL REFERENCES qr_tokens(id) ON DELETE RESTRICT,
    product      decal_product NOT NULL,
    quantity     smallint      NOT NULL DEFAULT 1 CHECK (quantity > 0),
    unit_gross_cents integer   NOT NULL
);

-- ---------------------------------------------------------------------------
-- Parking assistant (Parkuhr) — location auto-deleted 24h after session end
-- ---------------------------------------------------------------------------
CREATE TABLE parking_sessions (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vehicle_id       uuid        REFERENCES vehicles(id) ON DELETE SET NULL,
    location_enc     bytea,                          -- {"lat":..,"lng":..,"acc":..}
    key_version      smallint    NOT NULL DEFAULT 1,
    meter_expires_at timestamptz,
    reminders_min    smallint[]  NOT NULL DEFAULT '{10,5}',
    note             varchar(120),
    ended_at         timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX parking_sessions_due_idx ON parking_sessions(meter_expires_at) WHERE ended_at IS NULL;

-- ---------------------------------------------------------------------------
-- GDPR: consents, data-subject requests, audit
-- ---------------------------------------------------------------------------
CREATE TABLE consents (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose       varchar(40) NOT NULL,  -- 'terms','privacy','whatsapp_optin','sms_optin','marketing_email'
    doc_version   varchar(20) NOT NULL,
    granted_at    timestamptz NOT NULL DEFAULT now(),
    withdrawn_at  timestamptz
);
CREATE INDEX consents_user_idx ON consents(user_id, purpose);

CREATE TABLE data_subject_requests (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid        REFERENCES users(id) ON DELETE SET NULL,
    email_bidx    bytea,                       -- survives erasure to prove completion
    type          dsr_type    NOT NULL,
    status        dsr_status  NOT NULL DEFAULT 'received',
    due_at        timestamptz NOT NULL DEFAULT now() + interval '30 days',  -- Art. 12(3)
    completed_at  timestamptz,
    handled_by    uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- Append-only audit trail for staff actions & security events. Retained 12 months.
CREATE TABLE audit_logs (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id    uuid,
    actor_role  user_role,
    action      varchar(64) NOT NULL,          -- 'token.revoke','user.erase','ticket.assign',...
    entity      varchar(40) NOT NULL,
    entity_id   uuid,
    meta        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_entity_idx ON audit_logs(entity, entity_id);
CREATE INDEX audit_logs_created_idx ON audit_logs(created_at);

-- ---------------------------------------------------------------------------
-- Support
-- ---------------------------------------------------------------------------
CREATE TABLE support_tickets (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           uuid           REFERENCES users(id) ON DELETE SET NULL,
    channel           ticket_channel NOT NULL,
    subject           varchar(160)   NOT NULL,
    status            ticket_status  NOT NULL DEFAULT 'open',
    priority          smallint       NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 4),
    assigned_agent_id uuid           REFERENCES users(id) ON DELETE SET NULL,
    first_response_at timestamptz,
    resolved_at       timestamptz,
    created_at        timestamptz    NOT NULL DEFAULT now(),
    updated_at        timestamptz    NOT NULL DEFAULT now()
);
CREATE INDEX support_tickets_queue_idx ON support_tickets(status, priority, created_at);

CREATE TABLE ticket_messages (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id   uuid        NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
    author_id   uuid        REFERENCES users(id) ON DELETE SET NULL,
    is_internal boolean     NOT NULL DEFAULT false,
    body        text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Transactional outbox (exactly-once hand-off DB -> queue)
-- ---------------------------------------------------------------------------
CREATE TABLE outbox_events (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    topic         varchar(64) NOT NULL,          -- 'alert.created','alert.escalate', ...
    payload       jsonb       NOT NULL,
    available_at  timestamptz NOT NULL DEFAULT now(),
    processed_at  timestamptz,
    attempts      smallint    NOT NULL DEFAULT 0
);
CREATE INDEX outbox_pending_idx ON outbox_events(available_at) WHERE processed_at IS NULL;

-- ---------------------------------------------------------------------------
-- updated_at trigger
-- ---------------------------------------------------------------------------
CREATE FUNCTION touch_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at := now(); RETURN NEW; END $$;

CREATE TRIGGER users_touch         BEFORE UPDATE ON users          FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER organizations_touch BEFORE UPDATE ON organizations  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER vehicles_touch      BEFORE UPDATE ON vehicles       FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER subscriptions_touch BEFORE UPDATE ON subscriptions  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER tickets_touch       BEFORE UPDATE ON support_tickets FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ---------------------------------------------------------------------------
-- Retention job (run hourly by the worker; idempotent)
-- ---------------------------------------------------------------------------
CREATE FUNCTION run_retention() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    -- pseudonymous scanner reference: 24 h
    UPDATE alerts SET scanner_ref = NULL
     WHERE scanner_ref IS NOT NULL AND created_at < now() - interval '24 hours';
    -- free-text content: 7 days
    UPDATE alerts SET custom_message_enc = NULL
     WHERE custom_message_enc IS NOT NULL AND created_at < now() - interval '7 days';
    DELETE FROM alert_messages WHERE created_at < now() - interval '7 days';
    -- expire open alerts
    UPDATE alerts SET status = 'expired'
     WHERE status IN ('created','dispatched','delivered') AND expires_at < now();
    -- alert history visible to owner: 90 days
    DELETE FROM alerts WHERE created_at < now() - interval '90 days';
    -- parking location: 24 h after session end
    UPDATE parking_sessions SET location_enc = NULL
     WHERE location_enc IS NOT NULL AND ended_at < now() - interval '24 hours';
    -- shipping addresses: 90 days after delivery (HGB/AO invoice copies live in accounting, not here)
    UPDATE decal_orders SET shipping_address_enc = '\x'::bytea
     WHERE delivered_at < now() - interval '90 days' AND octet_length(shipping_address_enc) > 0;
    -- expired auth artefacts
    DELETE FROM magic_link_tokens WHERE expires_at < now() - interval '1 day';
    DELETE FROM sessions WHERE expires_at < now() - interval '7 days';
    DELETE FROM scanner_blocks WHERE expires_at < now();
    -- declined / unanswered emergency-contact invitations: 14 days
    DELETE FROM emergency_contacts
     WHERE consent IN ('pending','declined') AND consent_requested_at < now() - interval '14 days';
    -- audit trail: 12 months
    DELETE FROM audit_logs WHERE created_at < now() - interval '12 months';
    DELETE FROM outbox_events WHERE processed_at < now() - interval '7 days';
    -- execute due erasures
    DELETE FROM users WHERE status = 'pending_deletion' AND deletion_due_at < now();
END $$;

-- migrate:down
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;
