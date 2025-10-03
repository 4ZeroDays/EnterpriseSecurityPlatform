

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  

CREATE TABLE IF NOT EXISTS threat_detections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_ip INET NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    risk_score DECIMAL(5,2) NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    confidence DECIMAL(3,2) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    matched_rules TEXT[],
    recommendations TEXT[],
    log_data TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);


CREATE INDEX idx_threat_detections_source_ip ON threat_detections(source_ip);
CREATE INDEX idx_threat_detections_severity ON threat_detections(severity);
CREATE INDEX idx_threat_detections_created_at ON threat_detections(created_at DESC);
CREATE INDEX idx_threat_detections_risk_score ON threat_detections(risk_score DESC);
CREATE INDEX idx_threat_detections_metadata ON threat_detections USING gin(metadata);


CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(200) NOT NULL UNIQUE,
    pattern TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    enabled BOOLEAN DEFAULT true,
    score_weight DECIMAL(5,2) DEFAULT 50.0,
    description TEXT,
    created_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_detection_rules_enabled ON detection_rules(enabled);
CREATE INDEX idx_detection_rules_severity ON detection_rules(severity);

CREATE TABLE IF NOT EXISTS api_users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255),
    permissions TEXT[],
    api_key_hash VARCHAR(255),
    rate_limit INTEGER DEFAULT 1000,
    active BOOLEAN DEFAULT true,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_api_users_user_id ON api_users(user_id);
CREATE INDEX idx_api_users_active ON api_users(active);


CREATE TABLE IF NOT EXISTS system_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(100) NOT NULL,
    user_id VARCHAR(100),
    source_ip INET,
    details JSONB,
    severity VARCHAR(20),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_system_events_type ON system_events(event_type);
CREATE INDEX idx_system_events_created_at ON system_events(created_at DESC);
CREATE INDEX idx_system_events_user ON system_events(user_id);


CREATE TABLE IF NOT EXISTS alert_subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(100) NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    min_severity VARCHAR(20),
    webhook_url TEXT,
    email VARCHAR(255),
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS metrics_hourly (
    timestamp TIMESTAMP NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    value DECIMAL(12,2),
    labels JSONB,
    PRIMARY KEY (timestamp, metric_name)
);

CREATE INDEX idx_metrics_hourly_timestamp ON metrics_hourly(timestamp DESC);
CREATE INDEX idx_metrics_hourly_name ON metrics_hourly(metric_name);


CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


CREATE TRIGGER update_threat_detections_updated_at
    BEFORE UPDATE ON threat_detections
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_detection_rules_updated_at
    BEFORE UPDATE ON detection_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();


INSERT INTO detection_rules (name, pattern, severity, score_weight, description) VALUES
    ('SQL Injection', '(\bunion\b.*\bselect\b|\bor\b.*=.*\bor\b|''.*--|\bdrop\b.*\btable\b)', 'critical', 95.0, 'Detects SQL injection attempts'),
    ('XSS Attack', '<script[^>]*>.*?</script>|javascript:|onerror\s*=', 'high', 85.0, 'Cross-site scripting detection'),
    ('Path Traversal', '\.\./|\.\.\\|/etc/passwd|\\windows\\system32', 'high', 80.0, 'Directory traversal attempts'),
    ('Brute Force', '(failed.*login|authentication.*failed|invalid.*password).*{5,}', 'medium', 65.0, 'Brute force attack patterns'),
    ('Port Scanning', '(nmap|masscan|zmap|portscan)', 'medium', 60.0, 'Port scanning tool detection'),
    ('Malware Signature', '(eval\s*\(|base64_decode|exec\s*\(|system\s*\()', 'critical', 90.0, 'Common malware patterns')
ON CONFLICT (name) DO NOTHING;

-- for testing delete if you want 
INSERT INTO api_users (user_id, email, permissions, active) VALUES
    ('demo-analyst', 'analyst@example.com', ARRAY['read', 'analyze'], true),
    ('demo-admin', 'admin@example.com', ARRAY['read', 'analyze', 'admin'], true)
ON CONFLICT (user_id) DO NOTHING;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO secadmin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO secadmin;


DO $$
BEGIN
    RAISE NOTICE 'Database initialized successfully!';
    RAISE NOTICE 'Tables created: threat_detections, detection_rules, api_users, system_events, alert_subscriptions, metrics_hourly';
    RAISE NOTICE 'Sample rules and users inserted';
END $$;
