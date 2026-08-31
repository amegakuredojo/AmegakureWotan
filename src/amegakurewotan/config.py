import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class KuzuSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KUZU_", case_sensitive=False)
    
    database_path: Optional[str] = None

class OpsecSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPSEC_", case_sensitive=False)
    
    tor_proxy: Optional[str] = None
    tor_proxy_pool: Optional[str] = None
    tor_control_host: str = "127.0.0.1"
    tor_control_port: int = 9051
    user_agent_rotation: bool = True
    tls_fingerprint_policy: str = "standard"
    max_requests_per_second: float = 13.0
    enable_jitter: bool = False
    enable_opsec_blocking: bool = False


# Base directory: AMEWOTAN_DATA_DIR o ~/.amegakurewotan por defecto
_default_base = Path(os.environ.get("AMEWOTAN_DATA_DIR", str(Path.home() / ".amegakurewotan")))

class Config(BaseModel):
    base_dir: Path = Field(default=_default_base)
    kuzu: KuzuSettings
    opsec: OpsecSettings

    def init_dirs(self):
        """Ensure all required directories exist."""
        subdirs = [
            "bin",
            "core/runtime", "core/router", "core/policy", "core/session",
            "agents", "adapters", "graph/db", "graph/cypher", "graph/ingest",
            "opsec", "opsec/keys", "opsec/roe",
            "evidence", "evidence/screenshots", "evidence/html", "evidence/transcripts",
            "evidence/hashes", "evidence/video", "evidence/dfir", "reports", "sessions", "cache"
        ]
        for sd in subdirs:
            (self.base_dir / sd).mkdir(parents=True, exist_ok=True)

# Global config singleton
_config = None

def get_config() -> Config:
    global _config
    if _config is None:
        # Releer AMEWOTAN_DATA_DIR en tiempo de llamada
        base_dir = Path(os.environ.get("AMEWOTAN_DATA_DIR", str(Path.home() / ".amegakurewotan")))
        
        # Load settings from environment variables using BaseSettings
        kuzu_settings = KuzuSettings()
        if not kuzu_settings.database_path:
            kuzu_settings.database_path = os.environ.get(
                "KUZU_DATABASE_PATH", str(base_dir / "vault.kuzu")
            )
            
        opsec_settings = OpsecSettings()

        _config = Config(
            base_dir=base_dir,
            kuzu=kuzu_settings,
            opsec=opsec_settings
        )
    return _config

