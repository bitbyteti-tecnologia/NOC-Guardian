from fastapi import Header, HTTPException
import jwt
from datetime import datetime, timezone, timedelta
from passlib.hash import bcrypt
from .settings import settings
from .control_db import get_pool
ALGO='HS256'; SECRET=settings.jwt_secret
async def verify_agent_token(tenant_key: str, authorization: str | None):
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail='Missing Bearer token')
    token = authorization.split(' ',1)[1].strip()
    pool = await get_pool(); row = await pool.fetchrow('SELECT agent_token FROM tenant WHERE key=$1', tenant_key)
    if not row or row['agent_token'] != token: raise HTTPException(status_code=403, detail='Invalid agent token')
async def create_jwt(payload: dict, minutes=120):
    to_encode = payload.copy(); to_encode['exp'] = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return jwt.encode(to_encode, SECRET, algorithm=ALGO)
async def decode_jwt(authorization: str | None):
    if not authorization or not authorization.lower().startswith('bearer '): raise HTTPException(status_code=401, detail='Missing JWT')
    token = authorization.split(' ',1)[1].strip()
    try: return jwt.decode(token, SECRET, algorithms=[ALGO])
    except Exception: raise HTTPException(status_code=401, detail='Invalid JWT')
async def login_global(email: str, password: str):
    pool = await get_pool(); row = await pool.fetchrow('SELECT email,name,password_hash,role FROM system_user WHERE email=$1', email)
    if not row or not bcrypt.verify(password, row['password_hash']): raise HTTPException(status_code=401, detail='Credenciais inválidas')
    token = await create_jwt({'sub': row['email'], 'scope':'global', 'role': row['role']}); return {'token': token, 'user': {'email':row['email'],'name':row['name'],'role':row['role']}}
async def login_tenant(tenant_key: str, email: str, password: str):
    pool = await get_pool(); row = await pool.fetchrow('SELECT email,name,password_hash,role FROM tenant_user WHERE tenant_key=$1 AND email=$2', tenant_key, email)
    if not row or not bcrypt.verify(password, row['password_hash']): raise HTTPException(status_code=401, detail='Credenciais inválidas')
    token = await create_jwt({'sub': row['email'], 'scope':'tenant', 'tenant':tenant_key, 'role':row['role']}); return {'token': token, 'user': {'email':row['email'],'name':row['name'],'role':row['role'],'tenant':tenant_key}}
async def require_global_admin(auth: str | None):
    claims = await decode_jwt(auth)
    if claims.get('scope')!='global' or claims.get('role')!='admin': raise HTTPException(status_code=403, detail='Require global admin')
    return claims
async def require_tenant_role(auth: str | None, tenant: str, roles=('admin','operator','viewer')):
    claims = await decode_jwt(auth)
    if claims.get('scope')!='tenant' or claims.get('tenant')!=tenant or claims.get('role') not in roles: raise HTTPException(status_code=403, detail='Require tenant role')
    return claims
