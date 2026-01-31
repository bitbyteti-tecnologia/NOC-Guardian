from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional, Dict, List
from datetime import datetime, timezone, timedelta
from fastapi.middleware.cors import CORSMiddleware
from .settings import settings
from . import control_db
from .tenant_db import get_tenant_pool, migrate_tenant
from .auth import verify_agent_token, login_global, login_tenant, require_global_admin, require_tenant_role
import json
from .alert_worker import loop_forever
from .agents import router as agents_router
import asyncio

app = FastAPI(title='NOC Guardian (Pro+)', version='1.2.0')
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in settings.cors_origins.split(',')], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])
class MetricIn(BaseModel):
    ts: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    device_id: Optional[str] = None
    metric: str
    value: float
    labels: Optional[Dict[str, str]] = None
class MetricBulkIn(BaseModel): items: List[MetricIn]
class EventIn(BaseModel):
    ts: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    device_id: Optional[str] = None
    type: str
    source: Optional[str] = None
    severity: Optional[str] = None
    code: Optional[str] = None
    message: Optional[str] = None
    attrs: Optional[Dict[str, str]] = None
class TenantIn(BaseModel): key: str; name: str; db_dsn: str; agent_token: Optional[str] = None
class LoginReq(BaseModel): scope: str; email: str; password: str; tenant: Optional[str] = None
class AlertRuleIn(BaseModel): name: str; metric: str; operator: str; threshold: float; window_minutes: int = 5; severity: str; labels_filter: Optional[Dict[str, str]] = None; enabled: bool = True
class UserIn(BaseModel): email: str; name: str; password: str; role: str
@app.on_event('startup')
async def on_startup(): await control_db.get_pool(); await control_db.migrate(); asyncio.create_task(loop_forever(60))
@app.get('/api/v1/health')
async def health(): return {'status':'ok','time': datetime.now(timezone.utc).isoformat(), 'service':'backend'}
@app.post('/api/v1/auth/login')
async def login(req: LoginReq):
    if req.scope=='global': return await login_global(req.email, req.password)
    if req.scope=='tenant' and req.tenant: return await login_tenant(req.tenant, req.email, req.password)
    raise HTTPException(status_code=400, detail='Escopo inválido')
app.include_router(agents_router, prefix='/api/v1')
