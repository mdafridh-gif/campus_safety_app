-- PostgreSQL production schema. Media bytes belong in private object storage, never these tables.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;
CREATE TYPE user_role AS ENUM ('student','administrator');
CREATE TYPE incident_status AS ENUM ('active','acknowledged','responding','resolved','cancelled');
CREATE TYPE evidence_type AS ENUM ('audio','photo','video','text');
CREATE TYPE upload_state AS ENUM ('queued','uploading','uploaded','failed','metadata_only');
CREATE TYPE call_state AS ENUM ('initiated','ringing','answered','missed','failed','completed');

CREATE TABLE users (
  user_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), register_number varchar(80) UNIQUE,
  name varchar(180) NOT NULL, email citext NOT NULL UNIQUE, phone varchar(40),
  password_hash text, role user_role NOT NULL, department varchar(180), year_of_study varchar(32),
  status varchar(24) NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','disabled')),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE emergency_contacts (
  contact_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), name varchar(180) NOT NULL,
  department varchar(180), phone varchar(40) NOT NULL, email citext, priority smallint NOT NULL DEFAULT 1,
  is_active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE emergency_incidents (
  incident_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), display_id varchar(40) NOT NULL UNIQUE,
  user_id uuid NOT NULL REFERENCES users(user_id), incident_type varchar(100) NOT NULL,
  status incident_status NOT NULL DEFAULT 'active', latitude double precision, longitude double precision,
  location_accuracy real, campus_location varchar(240), description text NOT NULL DEFAULT '',
  assigned_officer_id uuid REFERENCES users(user_id), started_at timestamptz NOT NULL DEFAULT now(),
  acknowledged_at timestamptz, responding_at timestamptz, arrived_at timestamptz,
  resolved_at timestamptz, resolution_notes text, cancelled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((latitude IS NULL AND longitude IS NULL) OR (latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180))
);
CREATE INDEX incidents_status_started_idx ON emergency_incidents(status,started_at DESC);
CREATE INDEX incidents_user_started_idx ON emergency_incidents(user_id,started_at DESC);
CREATE INDEX incidents_assigned_status_idx ON emergency_incidents(assigned_officer_id,status);
CREATE TABLE evidence (
  evidence_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), incident_id uuid NOT NULL REFERENCES emergency_incidents(incident_id),
  type evidence_type NOT NULL, storage_key text, original_filename varchar(240), file_size bigint,
  duration_seconds real, upload_status upload_state NOT NULL DEFAULT 'queued', checksum_sha256 char(64),
  captured_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz,
  CHECK (file_size IS NULL OR file_size >= 0)
);
CREATE INDEX evidence_incident_created_idx ON evidence(incident_id,created_at DESC);
CREATE TABLE notifications (
  notification_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), incident_id uuid REFERENCES emergency_incidents(incident_id),
  recipient_id uuid REFERENCES users(user_id), title varchar(200) NOT NULL, message text NOT NULL,
  notification_type varchar(32) NOT NULL, delivery_status varchar(24) NOT NULL DEFAULT 'queued',
  is_read boolean NOT NULL DEFAULT false, sent_at timestamptz, read_at timestamptz,
  provider_reference text, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notifications_recipient_idx ON notifications(recipient_id,sent_at DESC);
CREATE TABLE emergency_calls (
  call_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), incident_id uuid NOT NULL REFERENCES emergency_incidents(incident_id),
  recipient_id uuid REFERENCES users(user_id), phone_number varchar(40) NOT NULL, call_status call_state NOT NULL,
  provider_call_id text, started_at timestamptz NOT NULL DEFAULT now(), ended_at timestamptz, duration_seconds integer,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE incident_timeline (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), incident_id uuid NOT NULL REFERENCES emergency_incidents(incident_id),
  actor_id uuid REFERENCES users(user_id), event_type varchar(80) NOT NULL, description text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX timeline_incident_created_idx ON incident_timeline(incident_id,created_at);
CREATE TABLE admin_actions (
  action_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), incident_id uuid NOT NULL REFERENCES emergency_incidents(incident_id),
  admin_id uuid NOT NULL REFERENCES users(user_id), action varchar(80) NOT NULL, notes text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE audit_logs (
  audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), actor_id uuid REFERENCES users(user_id),
  incident_id uuid REFERENCES emergency_incidents(incident_id), action varchar(120) NOT NULL,
  ip_address inet, user_agent text, metadata jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_incident_created_idx ON audit_logs(incident_id,created_at DESC);
CREATE TABLE user_sessions (
  session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES users(user_id),
  token_hash char(64) NOT NULL UNIQUE, expires_at timestamptz NOT NULL, revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE system_settings (
  setting_key varchar(100) PRIMARY KEY, setting_value jsonb NOT NULL, updated_by uuid REFERENCES users(user_id), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE evidence_retention_policies (
  policy_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), evidence_type evidence_type,
  retention_days integer NOT NULL CHECK (retention_days > 0), is_active boolean NOT NULL DEFAULT true,
  updated_by uuid REFERENCES users(user_id), updated_at timestamptz NOT NULL DEFAULT now()
);
