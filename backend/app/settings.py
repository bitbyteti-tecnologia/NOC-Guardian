from pydantic import BaseModel
import os
class Settings(BaseModel):
    api_host: str = os.getenv("API_HOST","0.0.0.0")
    api_port: int = int(os.getenv("API_PORT","8000"))
    database_url: str = os.getenv("DATABASE_URL","postgresql://nocuser:nocpass@db:5432/noc_control")
    cors_origins: str = os.getenv("CORS_ORIGINS","http://localhost")
    jwt_secret: str = os.getenv("JWT_SECRET","CHANGE_ME_DEV_SECRET")
settings = Settings()
