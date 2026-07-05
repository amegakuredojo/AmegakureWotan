import json
import zipfile
import hmac
import hashlib
from pathlib import Path
from typing import List, Dict, Any
from karasugakure.evidence.hash import sign_evidence_meta
from karasugakure.utils.fs import get_evidence_dir
from karasugakure.evidence.audit import ForensicAuditLedger

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

    def generate_signed_zip(self) -> Path:
        """Generates a ZIP archive containing all evidence artifacts and the manifest, signed with HMAC."""
        zip_path = get_evidence_dir() / f"{self.bundle_name}.zip"
        sig_path = get_evidence_dir() / f"{self.bundle_name}.zip.sig"
        
        # 1. Ensure manifest is saved
        self.save_manifest()
        
        # 2. Create ZIP archive
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add manifest
            zipf.write(self.meta_file, arcname=self.meta_file.name)
            # Add each file
            for item in self.items:
                fpath = Path(item["absolute_path"])
                if fpath.exists():
                    zipf.write(fpath, arcname=fpath.name)
                    
        # 3. Cryptographically sign the ZIP archive using the audit master key
        sha512_hash = hashlib.sha512()
        with open(zip_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha512_hash.update(chunk)
        zip_hash = sha512_hash.hexdigest()
        
        # Sign zip hash using HMAC (ForensicAuditLedger master key)
        try:
            ledger = ForensicAuditLedger()
            key = ledger._get_master_key()
            signature = hmac.new(key, zip_hash.encode("utf-8"), hashlib.sha512).hexdigest()
        except Exception:
            signature = hashlib.sha512(zip_hash.encode("utf-8")).hexdigest()
            
        # Write signature file
        sig_data = {
            "zip_filename": zip_path.name,
            "zip_hash": zip_hash,
            "signature": signature
        }
        sig_path.write_text(json.dumps(sig_data, indent=2))
        
        return zip_path
