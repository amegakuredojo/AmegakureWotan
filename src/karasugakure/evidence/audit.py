import os
import hmac
import hashlib
import json
import time
import subprocess
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from karasugakure.config import get_config

logger = logging.getLogger("karasugakure.evidence.audit")

class ForensicAuditLedger:
    def __init__(self):
        config = get_config()
        self.keys_dir = config.base_dir / "opsec" / "keys"
        self.key_path = self.keys_dir / "audit_master.key"
        self.ledger_path = config.base_dir / "evidence" / "audit_trail.log"
        self._init_master_key()

    def _init_master_key(self):
        """Initializes secure machine-specific master secret key for log integrity signing."""
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        if not self.key_path.exists():
            # Generate 64-bytes secure random key
            secret = os.urandom(64)
            # Write with 0600 permissions
            with open(os.open(self.key_path, os.O_CREAT | os.O_WRONLY, 0o600), "wb") as f:
                f.write(secret)
            logger.info("Forensic Audit master signature key generated.")

    def _get_master_key(self) -> bytes:
        with open(self.key_path, "rb") as f:
            return f.read()

    def _get_last_entry_hash(self) -> str:
        """Retrieves the hash of the last entry in the ledger to maintain hash-chain links."""
        if not self.ledger_path.exists() or self.ledger_path.stat().st_size == 0:
            return "0" * 64
            
        try:
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    if last_line:
                        record = json.loads(last_line)
                        return record.get("record_hash", "0" * 64)
        except Exception as e:
            logger.warning(f"Failed to trace hash-chain from ledger: {e}")
        return "0" * 64


    def log_execution(
        self,
        agent_name: str,
        action: str,
        parameters: Dict[str, Any],
        findings: List[Dict[str, Any]],
        evidence_files: List[Dict[str, Any]],
        proxy_route: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates a signed, hash-linked block representing an agent operation.
        Includes source class, confidence summary, route, tool version, and graph snapshot hash.
        Appends it to the immutable audit ledger.
        """
        config = get_config()
        timestamp = time.time()
        prev_hash = self._get_last_entry_hash()
        
        # 1. Source class extraction
        source_class = agent_name.lower()

        # 2. Confidence summary computation
        confidences = []
        for f in findings:
            if isinstance(f, dict):
                if "confidence" in f:
                    confidences.append(f["confidence"])
                elif "data" in f and isinstance(f["data"], dict) and "confidence" in f["data"]:
                    confidences.append(f["data"]["confidence"])
                elif "validation" in f and isinstance(f["validation"], dict) and "confidence" in f["validation"]:
                    confidences.append(f["validation"]["confidence"])

        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        confidence_summary = {
            "average_confidence": avg_confidence,
            "min_confidence": min(confidences) if confidences else 0.0,
            "max_confidence": max(confidences) if confidences else 0.0,
            "findings_count": len(findings)
        }

        # 3. Tool version hashes
        tool_versions = {}
        skills_base = config.base_dir.parent / "skills"
        if not skills_base.exists():
            skills_base = Path("/home/lugh/AmegakureDojo/Karasugakure/skills")
        for tool_path in [
            skills_base / "recon" / "amass_wrapper.sh",
            skills_base / "humint" / "sherlock_wrapper.sh",
            skills_base / "darkweb" / "onion_spider.py"
        ]:
            if tool_path.exists():
                try:
                    with open(tool_path, "rb") as f_tool:
                        tool_versions[tool_path.name] = hashlib.sha256(f_tool.read()).hexdigest()
                except Exception:
                    pass

        # 4. Graph database snapshot hash
        graph_snapshot_hash = "0" * 64
        try:
            from karasugakure.graph.export import export_to_json
            g_data = export_to_json()
            serialized_g = json.dumps(g_data, sort_keys=True)
            graph_snapshot_hash = hashlib.sha256(serialized_g.encode("utf-8")).hexdigest()
        except Exception:
            pass

        # Build core ledger payload
        payload = {
            "version": "1.1",
            "timestamp": timestamp,
            "agent": agent_name,
            "source_class": source_class,
            "confidence_summary": confidence_summary,
            "action": action,
            "parameters": parameters,
            "findings": findings,
            "evidence_files": evidence_files,
            "network_route": proxy_route or config.opsec.tor_proxy,
            "tool_versions": tool_versions,
            "graph_snapshot_hash": graph_snapshot_hash,
            "previous_record_hash": prev_hash
        }
        
        # Serialize payloads strictly to prevent canonicalization discrepancies
        serialized_payload = json.dumps(payload, sort_keys=True)
        
        # Compute HMAC signature using audit master key
        master_key = self._get_master_key()
        signature = hmac.new(master_key, serialized_payload.encode("utf-8"), hashlib.sha256).hexdigest()
        
        # Compile record
        record = {
            "payload": payload,
            "signature": signature,
            "record_hash": hashlib.sha256((serialized_payload + signature).encode("utf-8")).hexdigest()
        }
        
        # Try to sign with PGP/GPG key if available
        pgp_signature = self._try_pgp_sign(serialized_payload)
        if pgp_signature:
            record["pgp_signature"] = pgp_signature

        # Append to audit ledger (write-only append)
        with open(self.ledger_path, "a") as f:
            f.write(json.dumps(record) + "\n")
            
        logger.info(f"Forensic Audit record logged for {agent_name} -> {action} (Hash: {record['record_hash'][:8]})")
        return record

    def _try_pgp_sign(self, text: str) -> Optional[str]:
        """Tries to sign text using local PGP keys via gpg CLI if available."""
        try:
            proc = subprocess.Popen(
                ["gpg", "--clearsign", "--batch", "--yes"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = proc.communicate(input=text)
            if proc.returncode == 0:
                return stdout
        except Exception:
            pass # gpg command not available or key not selected
        return None

    def verify_ledger_integrity(self) -> bool:
        """
        Verifies the entire hash-chain link and HMAC signatures of the ledger log.
        Returns False if any modification, deletion, or insertion is detected.
        Saves a ledger diff summary to disk for operator review.
        """
        config = get_config()
        diff_path = config.base_dir / "evidence" / "ledger_diff_summary.json"
        
        diff_summary = {
            "is_corrupt": False,
            "timestamp": time.time(),
            "checked_records_count": 0,
            "corruptions": []
        }

        if not self.ledger_path.exists():
            # Write empty diff summary
            with open(diff_path, "w") as f_diff:
                json.dump(diff_summary, f_diff, indent=2)
            return True # Empty ledger is technically integral
            
        master_key = self._get_master_key()
        expected_prev_hash = "0" * 64
        line_num = 0
        
        try:
            with open(self.ledger_path, "r") as f:
                for line in f:
                    line_num += 1
                    line = line.strip()
                    if not line:
                        continue
                        
                    record = json.loads(line)
                    payload = record.get("payload")
                    sig = record.get("signature")
                    rec_hash = record.get("record_hash")
                    
                    if not payload or not sig or not rec_hash:
                        diff_summary["is_corrupt"] = True
                        diff_summary["corruptions"].append({
                            "line": line_num,
                            "reason": "Corrupt record structural fields missing",
                            "expected_fields": ["payload", "signature", "record_hash"]
                        })
                        continue
                        
                    # 1. Verify Prev Hash Link
                    actual_prev_hash = payload.get("previous_record_hash")
                    if actual_prev_hash != expected_prev_hash:
                        diff_summary["is_corrupt"] = True
                        diff_summary["corruptions"].append({
                            "line": line_num,
                            "reason": "Broken hash-chain link",
                            "expected_prev_hash": expected_prev_hash,
                            "actual_prev_hash": actual_prev_hash
                        })
                        
                    # 2. Verify HMAC Signature
                    serialized_payload = json.dumps(payload, sort_keys=True)
                    computed_sig = hmac.new(master_key, serialized_payload.encode("utf-8"), hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(sig, computed_sig):
                        diff_summary["is_corrupt"] = True
                        diff_summary["corruptions"].append({
                            "line": line_num,
                            "reason": "HMAC signature mismatch",
                            "expected_signature": computed_sig,
                            "actual_signature": sig
                        })
                        
                    # 3. Verify record hash
                    computed_hash = hashlib.sha256((serialized_payload + sig).encode("utf-8")).hexdigest()
                    if computed_hash != rec_hash:
                        diff_summary["is_corrupt"] = True
                        diff_summary["corruptions"].append({
                            "line": line_num,
                            "reason": "Record hash corruption",
                            "expected_hash": computed_hash,
                            "actual_hash": rec_hash
                        })
                        
                    expected_prev_hash = rec_hash
                    diff_summary["checked_records_count"] = line_num

            # Write diff summary for operator review
            with open(diff_path, "w") as f_diff:
                json.dump(diff_summary, f_diff, indent=2)

            if diff_summary["is_corrupt"]:
                logger.error(f"Forensic Audit Ledger Integrity check failed! Corruptions: {diff_summary['corruptions']}")
                return False

            logger.info(f"Forensic Audit Ledger verified successfully. Checked {line_num} records. Integrity: OK.")
            return True
        except Exception as e:
            logger.error(f"Error checking audit ledger integrity: {e}")
            diff_summary["is_corrupt"] = True
            diff_summary["corruptions"].append({"reason": f"Execution error: {e}"})
            with open(diff_path, "w") as f_diff:
                json.dump(diff_summary, f_diff, indent=2)
            return False

    def run_self_test(self) -> bool:
        """Runs periodic self-test on the ledger. Appends a self-test record, then verifies integrity."""
        logger.info("Executing ledger periodic self-test...")
        try:
            # Append self test block
            self.log_execution(
                agent_name="ledger_self_test",
                action="self_test",
                parameters={"timestamp": time.time()},
                findings=[{"status": "OK", "reason": "Periodic self-test trigger"}],
                evidence_files=[]
            )
            # Verify chain integrity
            return self.verify_ledger_integrity()
        except Exception as e:
            logger.error(f"Ledger self-test failed: {e}")
            return False

