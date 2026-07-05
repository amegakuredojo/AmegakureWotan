import hashlib
from pathlib import Path
from typing import Dict, Any

def calculate_sha512(filepath: Path) -> str:
    """Calculates SHA-512 hash of a file."""
    sha512_hash = hashlib.sha512()
    with open(filepath, "rb") as f:
        # Read in blocks
        for byte_block in iter(lambda: f.read(4096), b""):
            sha512_hash.update(byte_block)
    return sha512_hash.hexdigest()

def sign_evidence_meta(filepath: Path) -> Dict[str, Any]:
    """Generates metadata profile for frozen evidence."""
    h = calculate_sha512(filepath)
    stat = filepath.stat()
    return {
        "filename": filepath.name,
        "absolute_path": str(filepath.resolve()),
        "sha512": h,
        "bytes_size": stat.st_size,
        "created_time": stat.st_ctime
    }
