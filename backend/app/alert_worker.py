import asyncio, json
from datetime import datetime, timezone, timedelta
from .control_db import get_pool as get_control_pool
from .tenant_db import get_tenant_pool
OPS={'>':lambda a,b:a>b,'>=':lambda a,b:a>=b,'<':lambda a,b:a<b,'<=':lambda a,b:a<=b,'==':lambda a,b:a==b,'!=':lambda a,b:a!=b}
async def eval_rule(conn, r):
    cutoff=datetime.now(timezone.utc)-timedelta(minutes=r['window_minutes'])
    if r['labels_filter']:
        rows=await conn.fetch('SELECT value FROM metric WHERE metric=$1 AND ts>=$2 AND labels @> $3::jsonb', r['metric'], cutoff, json.dumps(r['labels_filter']))
    else:
        rows=await conn.fetch('SELECT value FROM metric WHERE metric=$1 AND ts>=$2', r['metric'], cutoff)
    if not rows: return
    vals=[x['value'] for x in rows if isinstance(x['value'],(int,float))]
    if not vals: return
    avg=sum(vals)/len(vals)
    fired=OPS.get(r['operator'],lambda *_:False)(avg,r['threshold'])
    ae=await conn.fetchrow('SELECT id FROM alert_event WHERE rule_id=$1 AND closed_at IS NULL ORDER BY opened_at DESC LIMIT 1', r['id'])
    if fired and not ae:
        await conn.execute('INSERT INTO alert_event(rule_id,opened_at,last_value,labels) VALUES($1,now(),$2,$3::jsonb)', r['id'], avg, json.dumps(r['labels_filter'] or {}))
    elif (not fired) and ae:
        await conn.execute('UPDATE alert_event SET closed_at=now(), last_value=$2 WHERE id=$1', ae['id'], avg)
async def run_once():
    cpool=await get_control_pool();
    async with cpool.acquire() as cconn:
        tenants=await cconn.fetch('SELECT key, db_dsn FROM tenant ORDER BY name')
    for t in tenants:
        tpool=await get_tenant_pool(t['db_dsn'])
        async with tpool.acquire() as conn:
            rules=await conn.fetch('SELECT id,name,metric,operator,threshold,window_minutes,severity,labels_filter,enabled FROM alert_rule WHERE enabled=TRUE')
            for r in rules: await eval_rule(conn,r)
async def loop_forever(interval=60):
    while True:
        try: await run_once()
        except Exception as e: print('[ALERT-WORKER]',e)
        await asyncio.sleep(interval)
