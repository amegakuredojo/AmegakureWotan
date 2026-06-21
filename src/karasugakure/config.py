import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Neo4jSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NEO4J_", case_sensitive=False)
    
    uri: str = "bolt://localhost:7687"
    username: str = "neo4j"
    password: Optional[str] = None
    database: str = "neo4j"

class OpsecSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPSEC_", case_sensitive=False)
    
    tor_proxy: str = "socks5h://127.0.0.1:9050"
    tor_proxy_pool: str = "socks5h://127.0.0.1:9050"
    user_agent_rotation: bool = True
    tls_fingerprint_policy: str = "random"

# Dentro del contenedor: KARASU_DATA_DIR=/data
# En host local: ~/.karasugakure
_default_base = Path(os.environ.get("KARASU_DATA_DIR", str(Path.home() / ".karasugakure")))

class Config(BaseModel):
    base_dir: Path = Field(default=_default_base)
    neo4j: Neo4jSettings
    opsec: OpsecSettings

    def init_dirs(self):
        """Ensure all required directories exist."""
        subdirs = [
            "bin",
            "core/runtime", "core/router", "core/policy", "core/session",
            "agents", "adapters", "graph/db", "graph/cypher", "graph/ingest",
            "opsec", "opsec/keys", "evidence/screenshots", "evidence/html", "evidence/transcripts",
            "evidence/hashes", "evidence/video", "reports", "sessions"
        ]
        for sd in subdirs:
            (self.base_dir / sd).mkdir(parents=True, exist_ok=True)

# Global config singleton
_config = None

def get_config() -> Config:
    global _config
    if _config is None:
        # Load settings from environment variables using BaseSettings
        neo4j_settings = Neo4jSettings()
        opsec_settings = OpsecSettings()
        
        # Verify required password
        if not neo4j_settings.password:
            raise ValueError(
                "NEO4J_PASSWORD must be set. No default allowed. "
                "Run: export NEO4J_PASSWORD='your_secure_pass'"
            )
            
        _config = Config(
            neo4j=neo4j_settings,
            opsec=opsec_settings
        )
    return _config
