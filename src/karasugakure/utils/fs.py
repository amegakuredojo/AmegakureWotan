import os
from pathlib import Path
from karasugakure.config import get_config

def get_base_dir() -> Path:
    return get_config().base_dir

def ensure_dir_exists(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path

def get_evidence_dir(subfolder: str = "") -> Path:
    config = get_config()
    p = config.base_dir / "evidence"
    if subfolder:
        p = p / subfolder
    return ensure_dir_exists(p)

def get_report_dir() -> Path:
    return ensure_dir_exists(get_config().base_dir / "reports")

def get_session_dir() -> Path:
    return ensure_dir_exists(get_config().base_dir / "sessions")
