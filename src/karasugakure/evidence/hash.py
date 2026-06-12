import hashlib
from pathlib import Path
from typing import Dict, Any

def calculate_sha256(filepath: Path) -> str:
    """Calculates SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read in blocks
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def sign_evidence_meta(filepath: Path) -> Dict[str, Any]:
    """Generates metadata profile for frozen evidence."""
    h = calculate_sha256(filepath)
    stat = filepath.stat()
    return {
        "filename": filepath.name,
        "absolute_path": str(filepath.resolve()),
        "sha256": h,
        "bytes_size": stat.st_size,
        "created_time": stat.st_ctime
    }
