import asyncpg
TENANT_INIT_SQL = (
    "CREATE EXTENSION IF NOT EXISTS pgcrypto;
"
    "CREATE TABLE IF NOT EXISTS metric (ts TIMESTAMPTZ NOT NULL, device_id TEXT, metric TEXT NOT NULL, value DOUBLE PRECISION NOT NULL, labels JSONB, PRIMARY KEY(ts, device_id, metric, COALESCE((labels->>'mnt'), ''), COALESCE((labels->>'target'), ''), COALESCE((labels->>'nic'), '')));
"
    "CREATE TABLE IF NOT EXISTS event (id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL DEFAULT now(), device_id TEXT, type TEXT, source TEXT, severity TEXT, code TEXT, message TEXT, attrs JSONB);
"
    "CREATE TABLE IF NOT EXISTS alert_rule (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, metric TEXT NOT NULL, operator TEXT NOT NULL, threshold DOUBLE PRECISION NOT NULL, window_minutes INT NOT NULL DEFAULT 5, severity TEXT NOT NULL, labels_filter JSONB, enabled BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ DEFAULT now());
"
    "CREATE TABLE IF NOT EXISTS alert_event (id BIGSERIAL PRIMARY KEY, rule_id BIGINT REFERENCES alert_rule(id) ON DELETE CASCADE, opened_at TIMESTAMPTZ NOT NULL DEFAULT now(), closed_at TIMESTAMPTZ, last_value DOUBLE PRECISION, labels JSONB, acked_at TIMESTAMPTZ, acked_by TEXT, closed_by TEXT);
"
)
_pools = {}
async def get_tenant_pool(dsn: str):
    pool = _pools.get(dsn)
    if pool is None:
        pool = await asyncpg.create_pool(dsn=dsn, min_size=1, max_size=5)
        _pools[dsn] = pool
    return pool
async def migrate_tenant(dsn: str):
    pool = await get_tenant_pool(dsn)
    async with pool.acquire() as conn:
        await conn.execute(TENANT_INIT_SQL)
