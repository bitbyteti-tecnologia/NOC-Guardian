
from fastapi import APIRouter
import io, tarfile
from .control_db import get_pool as get_control_pool

router = APIRouter()

AGENT_LINUX_TEMPLATE = r'''#!/usr/bin/env python3
import os, json, time
from datetime import datetime, timezone
from urllib.request import Request, urlopen
import psutil
API_BASE = os.environ.get('NOC_API_BASE', '{api_base}')
TOKEN    = os.environ.get('NOC_AGENT_TOKEN', '{agent_token}')
DEVICE_ID= os.environ.get('NOC_DEVICE_ID', '{device_id}')
INTERVAL = int(os.environ.get('NOC_INTERVAL', '60'))

def post_bulk(items, attempts=3):
    data = json.dumps({'items': items}).encode('utf-8')
    for i in range(attempts):
        try:
            req = Request(f"{API_BASE}/ingest/metrics", data=data, headers={'Content-Type':'application/json','Authorization':f'Bearer {TOKEN}'})
            with urlopen(req, timeout=5) as r: r.read(); return True
        except Exception: time.sleep(2**i)
    return False

def g(m, v, l=None):
    return {'ts': datetime.now(timezone.utc).isoformat(), 'device_id': DEVICE_ID, 'metric': m, 'value': float(v), 'labels': l or {}}
_prev=None; _prev_ts=None

def throughput():
    global _prev, _prev_ts
    now=time.time(); c=psutil.net_io_counters(pernic=True); out={}
    if _prev and _prev_ts:
        dt=max(0.001, now-_prev_ts)
        for nic, v in c.items():
            if nic in _prev:
                out[nic]=((v.bytes_recv-_prev[nic].bytes_recv)/dt,(v.bytes_sent-_prev[nic].bytes_sent)/dt)
    _prev=c; _prev_ts=now
    return out

def main():
    while True:
        items=[]
        cpu=psutil.cpu_percent(interval=None); items.append(g('cpu_percent', cpu, {'os':'linux'}))
        vm=psutil.virtual_memory(); items.append(g('mem_percent', vm.percent, {'os':'linux'}))
        for p in psutil.disk_partitions(all=False):
            try:
                u=psutil.disk_usage(p.mountpoint)
                items.append(g('disk_used_pct', u.percent, {'os':'linux','mnt':p.mountpoint}))
            except PermissionError: pass
        for nic,(rx,tx) in throughput().items():
            items.append(g('net_rx_bps', rx, {'os':'linux','nic':nic}))
            items.append(g('net_tx_bps', tx, {'os':'linux','nic':nic}))
        post_bulk(items)
        time.sleep(INTERVAL)

if __name__=='__main__':
    main()
'''

SYSTEMD_TEMPLATE = '''[Unit]
Description=NOC Guardian Agent (Linux)
After=network-online.target
Wants=network-online.target
[Service]
Environment=NOC_API_BASE={api_base}
Environment=NOC_AGENT_TOKEN={agent_token}
Environment=NOC_DEVICE_ID={device_id}
Environment=NOC_INTERVAL=60
ExecStart=/usr/bin/python3 /usr/local/bin/noc-agent-linux
Restart=always
RestartSec=10
User=root
[Install]
WantedBy=multi-user.target
'''

AGENT_HOST_TOKEN_INIT_SQL = (
    'CREATE TABLE IF NOT EXISTS agent_host_token ('
    'id UUID PRIMARY KEY DEFAULT gen_random_uuid(),'
    'tenant_key TEXT NOT NULL REFERENCES tenant(key) ON DELETE CASCADE,'
    'device_id TEXT NOT NULL,'
    'token TEXT NOT NULL,'
    'revoked BOOLEAN NOT NULL DEFAULT FALSE,'
    'created_at TIMESTAMPTZ DEFAULT now(),'
    'UNIQUE(tenant_key, device_id)'
    ');'
)

@router.post('/{tenant}/agents/token')
async def create_or_rotate_token(tenant: str, device_id: str):
    pool = await get_control_pool()
    async with pool.acquire() as conn:
        import secrets, string
        tok = ''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(48))
        await conn.execute(AGENT_HOST_TOKEN_INIT_SQL)
        await conn.execute(
            '''
            INSERT INTO agent_host_token(tenant_key, device_id, token, revoked)
            VALUES($1,$2,$3,false)
            ON CONFLICT(tenant_key, device_id)
            DO UPDATE SET token=EXCLUDED.token, revoked=false, created_at=now()
            ''',
            tenant, device_id, tok
        )
        return {'device_id': device_id, 'token': tok}

@router.post('/{tenant}/agents/token/revoke')
async def revoke_token(tenant: str, device_id: str):
    pool = await get_control_pool()
    async with pool.acquire() as conn:
        await conn.execute(AGENT_HOST_TOKEN_INIT_SQL)
        await conn.execute(
            'UPDATE agent_host_token SET revoked=true WHERE tenant_key=$1 AND device_id=$2',
            tenant, device_id
        )
        return {'ok': True}

@router.get('/{tenant}/agents/linux')
async def download_linux_agent(tenant: str, device_id: str):
    pool = await get_control_pool()
    async with pool.acquire() as conn:
        await conn.execute(AGENT_HOST_TOKEN_INIT_SQL)
        row = await conn.fetchrow(
            'SELECT token FROM agent_host_token WHERE tenant_key=$1 AND device_id=$2 AND revoked=false',
            tenant, device_id
        )
        if not row:
            res = await create_or_rotate_token(tenant, device_id)
            token = res['token']
        else:
            token = row['token']
    api_base = f'/api/v1/{tenant}'
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode='w:gz') as tar:
        agent_py = AGENT_LINUX_TEMPLATE.format(api_base=api_base, agent_token=token, device_id=device_id).encode('utf-8')
        unit = SYSTEMD_TEMPLATE.format(api_base=api_base, agent_token=token, device_id=device_id).encode('utf-8')
        def add_bytes(name, data):
            info = tarfile.TarInfo(name=name); info.size=len(data)
            tar.addfile(info, io.BytesIO(data))
        add_bytes('noc-agent-linux.py', agent_py)
        add_bytes('noc-agent-linux.service', unit)
        readme = f'Instalação:
  sudo cp noc-agent-linux.py /usr/local/bin/noc-agent-linux && sudo chmod +x /usr/local/bin/noc-agent-linux
  sudo cp noc-agent-linux.service /etc/systemd/system/
  sudo systemctl daemon-reload && sudo systemctl enable --now noc-agent-linux

DeviceID: {device_id}
'
        add_bytes('README.txt', readme.encode('utf-8'))
    bio.seek(0)
    from fastapi.responses import StreamingResponse
    headers={'Content-Disposition': f'attachment; filename="linux_agent_{tenant}_{device_id}.tar.gz"'}
    return StreamingResponse(bio, media_type='application/gzip', headers=headers)
