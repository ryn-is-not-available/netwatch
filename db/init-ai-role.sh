#!/bin/sh
# Runs once, after 01-init.sql, when the database volume is first initialized.
# Creates the read-only role the AI diagnostic worker connects as: it can read only the
# columns diagnosis needs (no users, no audit log, no certificates) and cannot write.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<EOSQL
CREATE ROLE netwatch_ai LOGIN PASSWORD '${AI_DB_PASSWORD:-netwatch_ai_dev_pass}';
ALTER ROLE netwatch_ai SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE "$POSTGRES_DB" TO netwatch_ai;
GRANT USAGE ON SCHEMA public TO netwatch_ai;
GRANT SELECT (node_id, health_status, last_heartbeat, data_ip) ON nodes TO netwatch_ai;
GRANT SELECT ON topology_links, desired_topology_links, probe_results, path_traces TO netwatch_ai;
GRANT SELECT (alert_id, severity, status, message, affected_node_id, created_at) ON alerts TO netwatch_ai;
EOSQL
