import os
from pathlib import Path
from pydantic import BaseModel, Field

class Neo4jConfig(BaseModel):
    uri: str = Field(default="bolt://localhost:7687", env="NEO4J_URI")
    username: str = Field(default="neo4j", env="NEO4J_USERNAME")
    password: str = Field(default="password", env="NEO4J_PASSWORD")
    database: str = Field(default="neo4j", env="NEO4J_DATABASE")

class OpsecConfig(BaseModel):
    tor_proxy: str = "socks5h://127.0.0.1:9050"
    user_agent_rotation: bool = True
    tls_fingerprint_policy: str = "random"

class Config(BaseModel):
    base_dir: Path = Field(default=Path.home() / ".karasugakure")
    neo4j: Neo4jConfig = Field(default_factory=Neo4jConfig)
    opsec: OpsecConfig = Field(default_factory=OpsecConfig)

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
        # Load environment overrides if any
        uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        username = os.environ.get("NEO4J_USERNAME", "neo4j")
        password = os.environ.get("NEO4J_PASSWORD", "password")
        database = os.environ.get("NEO4J_DATABASE", "neo4j")
        
        _config = Config(
            neo4j=Neo4jConfig(
                uri=uri,
                username=username,
                password=password,
                database=database
            )
        )
    return _config
