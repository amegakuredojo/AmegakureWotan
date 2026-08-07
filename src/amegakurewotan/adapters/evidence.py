import logging
from pathlib import Path
from typing import Dict, Any
from amegakurewotan.utils.fs import get_evidence_dir

logger = logging.getLogger("amegakurewotan.adapters.evidence")

class EvidenceAdapter:
    def __init__(self):
        self.base_dir = get_evidence_dir()

    def store_raw_evidence(self, filename: str, content: bytes, folder: str = "") -> Path:
        """Stores binary or text evidence files into the evidence vault."""
        target_dir = get_evidence_dir(folder)
        filepath = target_dir / filename
        try:
            with open(filepath, "wb") as f:
                f.write(content)
            logger.info(f"Stored evidence file: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Failed to store evidence file {filename}: {e}")
            raise e
