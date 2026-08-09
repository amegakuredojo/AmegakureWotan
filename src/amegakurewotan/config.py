import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class KuzuSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KUZU_", case_sensitive=False)
    
    database_path: str = "/data/amegakurewotan_vault.kuzu"

class OpsecSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPSEC_", case_sensitive=False)
    
    tor_proxy: str = "socks5h://127.0.0.1:9050"
    tor_proxy_pool: str = "socks5h://127.0.0.1:9050"
    tor_control_host: str = "127.0.0.1"
    tor_control_port: int = 9051
    user_agent_rotation: bool = True
    tls_fingerprint_policy: str = "random"
    # Rate limit DURO de salida (requests/segundo) para TODA petición HTTP/S.
    # Doctrina AmegakureDojo: máximo 13 req/s, SIN ráfagas — nunca saturar la red
    # del objetivo. Aplicado en utils.net vía un token-bucket global thread-safe.
    max_requests_per_second: float = 13.0

# Dentro del contenedor: AMEWOTAN_DATA_DIR=/data
# En host local: ~/.amegakurewotan
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
            "evidence/hashes", "evidence/video", "evidence/dfir", "reports", "sessions"
        ]
        for sd in subdirs:
            (self.base_dir / sd).mkdir(parents=True, exist_ok=True)

# Global config singleton
_config = None

def get_config() -> Config:
    global _config
    if _config is None:
        # Load settings from environment variables using BaseSettings
        kuzu_settings = KuzuSettings()
        opsec_settings = OpsecSettings()

        # Releer AMEWOTAN_DATA_DIR en tiempo de llamada (no en import): así, tras
        # un reset de singleton (_config=None), get_config() honra el env actual.
        # Esto hace efectivos los overrides de tests/despliegue y evita que un
        # valor congelado en import-time apunte a un base_dir equivocado.
        base_dir = Path(os.environ.get("AMEWOTAN_DATA_DIR", str(Path.home() / ".amegakurewotan")))

        _config = Config(
            base_dir=base_dir,
            kuzu=kuzu_settings,
            opsec=opsec_settings
        )
    return _config
