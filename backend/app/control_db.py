import asyncpg
from .settings import settings
_pool = None
async def get_pool():
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(dsn=settings.database_url, min_size=1, max_size=5)
    return _pool
INIT_SQL = (
    "CREATE EXTENSION IF NOT EXISTS pgcrypto;
"
    "CREATE TABLE IF NOT EXISTS tenant (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), key TEXT UNIQUE NOT NULL, name TEXT NOT NULL, db_dsn TEXT NOT NULL, agent_token TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now());
"
    "CREATE TABLE IF NOT EXISTS system_user (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin','operator')), created_at TIMESTAMPTZ DEFAULT now());
"
    "CREATE TABLE IF NOT EXISTS tenant_user (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_key TEXT NOT NULL REFERENCES tenant(key) ON DELETE CASCADE, email TEXT NOT NULL, name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('admin','operator','viewer')), UNIQUE(tenant_key, email), created_at TIMESTAMPTZ DEFAULT now());
"
)
async def migrate():
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(INIT_SQL)
