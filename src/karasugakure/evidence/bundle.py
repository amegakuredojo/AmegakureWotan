import json
from pathlib import Path
from typing import List, Dict, Any
from karasugakure.evidence.hash import sign_evidence_meta
from karasugakure.utils.fs import get_evidence_dir

class EvidenceBundler:
    def __init__(self, bundle_name: str = "case_bundle"):
        self.bundle_name = bundle_name
        self.meta_file = get_evidence_dir() / f"{bundle_name}_manifest.json"
        self.items: List[Dict[str, Any]] = []

    def add_file(self, filepath: Path):
        """Adds a file to bundle, calculating its metadata signature."""
        meta = sign_evidence_meta(filepath)
        self.items.append(meta)
        self.save_manifest()

    def save_manifest(self):
        """Writes manifest metadata list to case_bundle_manifest.json."""
        manifest = {
            "bundle": self.bundle_name,
            "count": len(self.items),
            "files": self.items
        }
        with open(self.meta_file, "w") as f:
            json.dump(manifest, f, indent=2)
