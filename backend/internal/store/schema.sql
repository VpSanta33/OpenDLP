-- OpenDLP 数据库结构 v1

-- 配置类数据（JSONB 文档）
CREATE TABLE documents (
    name       text PRIMARY KEY,
    data       jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- DLP 事件
CREATE SEQUENCE incident_seq START 48001;
CREATE TABLE incidents (
    id        text PRIMARY KEY,
    ts        timestamptz NOT NULL,
    user_name text NOT NULL DEFAULT '',
    dept      text NOT NULL DEFAULT '',
    host      text NOT NULL DEFAULT '',
    ip        text NOT NULL DEFAULT '',
    channel   text NOT NULL,
    dest      text NOT NULL DEFAULT '',
    data_type text NOT NULL DEFAULT '',
    file      text NOT NULL DEFAULT '',
    size      text NOT NULL DEFAULT '',
    matches   integer NOT NULL DEFAULT 0,
    severity  text NOT NULL,
    action    text NOT NULL,
    status    text NOT NULL,
    policy    text NOT NULL DEFAULT '',
    policy_id text NOT NULL DEFAULT '',
    handler   text NOT NULL DEFAULT '',
    closed_at timestamptz
);
CREATE INDEX incidents_ts_idx ON incidents (ts DESC);
CREATE INDEX incidents_sev_status_idx ON incidents (severity, status);
CREATE INDEX incidents_user_idx ON incidents (user_name, ts DESC);

-- 外发检测量（按小时、渠道、数据类型聚合）
CREATE TABLE detections_hourly (
    h         timestamptz NOT NULL,
    channel   text NOT NULL,
    data_type text NOT NULL,
    total     integer NOT NULL DEFAULT 0,
    allowed   integer NOT NULL DEFAULT 0,
    audited   integer NOT NULL DEFAULT 0,
    encrypted integer NOT NULL DEFAULT 0,
    blocked   integer NOT NULL DEFAULT 0,
    PRIMARY KEY (h, channel, data_type)
);

-- 审计日志：SHA-256 哈希链，只允许追加
CREATE TABLE audit_log (
    seq    bigint PRIMARY KEY,
    id     text NOT NULL UNIQUE,
    ts     timestamptz NOT NULL,
    op     text NOT NULL,
    role   text NOT NULL DEFAULT '',
    type   text NOT NULL,
    detail text NOT NULL,
    ip     text NOT NULL DEFAULT '',
    ok     boolean NOT NULL,
    reason text NOT NULL DEFAULT '',
    prev   text NOT NULL,
    hash   text NOT NULL
);
CREATE SEQUENCE audit_seq;
CREATE INDEX audit_type_idx ON audit_log (type, seq DESC);

CREATE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log 只允许追加，禁止修改或删除';
END
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

-- 登录会话（仅保存令牌的 SHA-256 摘要）
CREATE TABLE sessions (
    token_hash text PRIMARY KEY,
    acc        text NOT NULL,
    role       text NOT NULL,
    ip         text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL
);
CREATE INDEX sessions_acc_idx ON sessions (acc);
