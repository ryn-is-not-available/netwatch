CREATE EXTENSION IF NOT EXISTS btree_gist;
CREATE EXTENSION IF NOT EXISTS timescaledb;


-- Layer 1

CREATE TABLE nodes (
    node_id VARCHAR(255) PRIMARY KEY,
    ip_address VARCHAR(255) NOT NULL,
    health_status VARCHAR(255) NOT NULL
        CHECK (health_status IN ('enrolled', 'healthy', 'degraded', 'offline', 'revoked')),
    active_certificate TEXT,
    last_heartbeat TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE network_interfaces (
    interface_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id VARCHAR(255) NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,

    name VARCHAR(64) NOT NULL,
    interface_type VARCHAR(32) NOT NULL DEFAULT 'physical',
    mac_address MACADDR NOT NULL,

    ip_addresses INET[] NOT NULL DEFAULT '{}',

    link_speed_mbps BIGINT,

    admin_status VARCHAR(16) NOT NULL DEFAULT 'up'
        CHECK (admin_status IN ('up', 'down')),
    oper_status VARCHAR(16) NOT NULL DEFAULT 'up'
        CHECK (oper_status IN ('up', 'down', 'degraded', 'dormant')),

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uiq_node_interface UNIQUE (node_id, name)
);


CREATE INDEX idx_network_interfaces_node ON network_interfaces (node_id);
CREATE INDEX idx_network_interfaces_ips ON network_interfaces USING gin (ip_addresses);

-- Layer 2


CREATE TABLE topology_links (
    link_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    src_node_id VARCHAR(255) NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    dst_node_id VARCHAR(255) NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,

    status VARCHAR(255) NOT NULL
        CHECK (status IN ('up', 'down', 'degraded')),
    latency_ms NUMERIC(10, 2),
    packet_loss_pct NUMERIC(5, 2),

    valid_during TSTZRANGE NOT NULL,
    recorded_during TSTZRANGE NOT NULL,

    CONSTRAINT no_overlapping_links EXCLUDE USING gist (
        src_node_id WITH =,
        dst_node_id WITH =,
        valid_during WITH &&
    ),

    CONSTRAINT no_self_links CHECK (src_node_id <> dst_node_id)
);

CREATE INDEX idx_topology_links_temporal ON topology_links USING gist (src_node_id,dst_node_id,valid_during);

-- Operator-declared intent (POST /topology/desired), diffed against topology_links for drift.
CREATE TABLE desired_topology_links (
    src_node_id VARCHAR(255) NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    dst_node_id VARCHAR(255) NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    admin_cost NUMERIC(10, 2) NOT NULL DEFAULT 1.0,
    expected_latency_ms NUMERIC(10, 2) NOT NULL DEFAULT 5.0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (src_node_id, dst_node_id),
    CONSTRAINT no_self_desired_links CHECK (src_node_id <> dst_node_id)
);

-- Layer 3

CREATE TABLE alerts (
    alert_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    affected_node_id VARCHAR(255) REFERENCES nodes(node_id) ON DELETE CASCADE,
    affected_link_id UUID REFERENCES topology_links(link_id) ON DELETE CASCADE,
    severity VARCHAR(255) NOT NULL
        CHECK (severity IN ('info','warning','critical')),
    status VARCHAR(255) NOT NULL 
        CHECK (status IN ('new', 'acknowledged', 'resolved')),
    message TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_alerts_status ON alerts (status);
CREATE INDEX idx_alerts_severity ON alerts (severity);

-- AlertEvaluator state: persisted PENDING/FIRING timers keyed by rule fingerprint.
CREATE TABLE alert_timers (
    fingerprint VARCHAR(255) PRIMARY KEY,
    state VARCHAR(32) NOT NULL CHECK (state IN ('PENDING', 'FIRING')),
    pending_since TIMESTAMPTZ NOT NULL,
    fired_at TIMESTAMPTZ,
    alert_id UUID REFERENCES alerts(alert_id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE recommendations (
    recommendation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    alert_id UUID REFERENCES alerts(alert_id) ON DELETE CASCADE,
    link_id UUID REFERENCES topology_links(link_id) ON DELETE CASCADE,

    diagnosis TEXT NOT NULL,
    suggested_fix TEXT NOT NULL,

    status VARCHAR(255) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'applied', 'dismissed')),

    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    applied_at TIMESTAMPTZ
);

CREATE INDEX idx_recommendations_status ON recommendations (status);
CREATE INDEX idx_recommendations_alert ON recommendations (alert_id);


CREATE TABLE leader_epoch (
    epoch BIGINT PRIMARY KEY,
    leader_id VARCHAR(255) NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(255) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'expired', 'revoked'))
);

CREATE INDEX idx_Leader_epoch_status ON leader_epoch (status) WHERE status = 'active'; 



CREATE TABLE node_commands (
    command_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_node_id VARCHAR(255) REFERENCES nodes(node_id) ON DELETE CASCADE,

    command_type VARCHAR(255) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',

    leader_epoch BIGINT NOT NULL REFERENCES leader_epoch(epoch),

    status VARCHAR(255) NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','delivered','executed','failed')),
    result_output TEXT,


    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    executed_at TIMESTAMPTZ
);

CREATE INDEX idx_node_commands_queue ON node_commands (target_node_id, status);
CREATE INDEX idx_node_commands_epoch ON node_commands (leader_epoch);



CREATE TABLE path_traces (
    trace_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    src_node_id VARCHAR(255) NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    dst_node_id VARCHAR(255) NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    
    hops JSONB NOT NULL DEFAULT '[]',
    
    packet_loss_pct NUMERIC(5, 2),
    avg_latency_ms NUMERIC(10, 2),
    
    captured_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_path_traces_nodes_time ON path_traces (src_node_id, dst_node_id, captured_at DESC);


CREATE TABLE audit_log (
    log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id VARCHAR(255) NOT NULL,
    action_type VARCHAR(255) NOT NULL,
    target_entity VARCHAR(255) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}',
    ip_address INET NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_log_type_time ON audit_log (action_type, created_at DESC);
REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;


-- Layer 4


CREATE TABLE probe_results (
    time TIMESTAMPTZ NOT NULL,
    src_node_id VARCHAR(255) NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,
    dst_node_id VARCHAR(255) NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,

    probe_type VARCHAR(255) NOT NULL,
    latency_ms NUMERIC(10, 2),
    packet_loss_pct NUMERIC(5, 2),
    jitter_ms NUMERIC(10, 2),

    success BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE node_metrics (
    time TIMESTAMPTZ NOT NULL,
    node_id VARCHAR(255) NOT NULL,
    boot_id UUID NOT NULL,
    seq_id BIGINT NOT NULL,
    cpu_usage_pct NUMERIC(5, 2),
    memory_usage_pct NUMERIC(5, 2),
    uptime_seconds BIGINT,
    data_iface VARCHAR(64),
    rx_bytes BIGINT,
    tx_bytes BIGINT,
    rx_drops BIGINT,
    tx_drops BIGINT
);

CREATE TABLE interface_metrics (
    time TIMESTAMPTZ NOT NULL,
    interface_id UUID NOT NULL REFERENCES network_interfaces(interface_id) ON DELETE CASCADE,
    interface_name VARCHAR(64) NOT NULL,
    node_id VARCHAR(255) NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE,

    rx_bytes BIGINT,
    tx_bytes BIGINT,
    rx_errors BIGINT,
    tx_errors BIGINT
);



SELECT create_hypertable('probe_results', 'time', if_not_exists => TRUE);
SELECT create_hypertable('node_metrics', 'time', if_not_exists => TRUE);
SELECT create_hypertable('interface_metrics', 'time', if_not_exists => TRUE);

CREATE UNIQUE INDEX uq_node_metrics_tick
    ON node_metrics (time, node_id, boot_id, seq_id);



ALTER TABLE probe_results SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'src_node_id, dst_node_id',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('probe_results', INTERVAL '7 days');
SELECT add_retention_policy('probe_results', INTERVAL '30 days');

ALTER TABLE node_metrics SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'node_id',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('node_metrics', INTERVAL '7 days');
SELECT add_retention_policy('node_metrics', INTERVAL '30 days');

ALTER TABLE interface_metrics SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'node_id, interface_name',
    timescaledb.compress_orderby = 'time DESC'
);
SELECT add_compression_policy('interface_metrics', INTERVAL '7 days');
SELECT add_retention_policy('interface_metrics', INTERVAL '30 days');


DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'netwatch_app') THEN
        CREATE ROLE netwatch_app LOGIN PASSWORD 'netwatch_dev';
    END IF;
END
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO netwatch_app;
REVOKE UPDATE, DELETE ON audit_log FROM netwatch_app, PUBLIC;