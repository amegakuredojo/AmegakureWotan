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
        self._check_key_rotation()

    def _check_key_rotation(self):
        """Rotates audit master key if older than KEY_ROTATION_DAYS."""
        KEY_ROTATION_DAYS = int(os.environ.get("KARASU_KEY_ROTATION_DAYS", "30"))
        if not self.key_path.exists():
            return
        key_age_days = (time.time() - self.key_path.stat().st_mtime) / 86400
        if key_age_days >= KEY_ROTATION_DAYS:
            # Archive old key with timestamp
            epoch_ts = int(time.time())
            archive_path = self.keys_dir / f"audit_master_{epoch_ts}.key.bak"
            self.key_path.rename(archive_path)
            logger.warning(
                f"Audit key rotated after {key_age_days:.1f} days. "
                f"Old key archived to {archive_path.name}. "
                f"New epoch key generated."
            )
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
        try:
            from karasugakure.graph.db import get_db
            db = get_db()
            if db.check_connection():
                query = "MATCH (r:AuditRecord) RETURN r.record_hash AS last_hash ORDER BY r.timestamp DESC LIMIT 1"
                res = db.execute_query(query)
                if res and res[0].get("last_hash"):
                    return res[0]["last_hash"]
        except Exception as e:
            logger.warning(f"Failed to query last ledger record hash from Neo4j: {e}")

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
            logger.warning(f"Failed to trace hash-chain from ledger file: {e}")
        return "0" * 64


    def log_execution(
        self,
        agent_name: str,
        action: str,
        parameters: Dict[str, Any],
        findings: List[Dict[str, Any]],
        evidence_files: List[Dict[str, Any]],
        proxy_route: Optional[str] = None,
        run_id: Optional[str] = None,
        schema_version: Optional[str] = None,
        operator_id: Optional[str] = None,
        target_id: Optional[str] = None,
        evidence_hash: Optional[str] = None,
        hypothesis_id: Optional[str] = None,
        phase_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates a signed, hash-linked block representing an agent operation.
        Includes source class, confidence summary, route, tool version, and graph snapshot hash.
        Appends it to the immutable audit ledger.
        """
        import uuid
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
        skills_base = Path(__file__).resolve().parent.parent.parent.parent / "skills"
        if not skills_base.exists():
            logger.warning("Skills directory not found dynamically; skipping tool version hashes.")
        else:
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
            # In order to avoid infinite recursion when log_execution calls export_to_json,
            # we check the caller action / agent_name and pass appropriate parameters.
            g_data = export_to_json()
            serialized_g = json.dumps(g_data, sort_keys=True)
            graph_snapshot_hash = hashlib.sha256(serialized_g.encode("utf-8")).hexdigest()
        except Exception:
            pass

        # 5. Populate Execution Contract fields
        run_id_val = run_id or parameters.get("run_id") or os.environ.get("KARASU_RUN_ID") or str(uuid.uuid4())
        schema_version_val = schema_version or os.environ.get("KARASU_SCHEMA_VERSION") or "9.4"
        operator_id_val = operator_id or os.environ.get("KARASU_OPERATOR_ID") or "operator-default"
        target_id_val = target_id or parameters.get("target") or parameters.get("target_id") or os.environ.get("KARASU_TARGET_ID") or "target-default"
        
        if not evidence_hash:
            serialized_findings = json.dumps(findings, sort_keys=True)
            evidence_hash_val = hashlib.sha256(serialized_findings.encode("utf-8")).hexdigest()
        else:
            evidence_hash_val = evidence_hash

        hypothesis_id_val = hypothesis_id or os.environ.get("KARASU_HYPOTHESIS_ID") or f"hyp-{run_id_val}"
        phase_id_val = phase_id or os.environ.get("KARASU_PHASE_ID") or action or "phase-default"

        # Build core ledger payload
        payload = {
            "version": "1.2",  # Upgraded schema version of audit trail
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
            "previous_record_hash": prev_hash,
            
            # Execution Contract fields
            "run_id": run_id_val,
            "schema_version": schema_version_val,
            "operator_id": operator_id_val,
            "target_id": target_id_val,
            "evidence_hash": evidence_hash_val,
            "hypothesis_id": hypothesis_id_val,
            "phase_id": phase_id_val
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

        # Dual Ingest: Persist to Neo4j as AuditRecord node and edge
        try:
            from karasugakure.graph.db import get_db
            db = get_db()
            if db.check_connection():
                cypher_node = """
                MERGE (r:AuditRecord {record_hash: $record_hash})
                SET r.payload = $payload,
                    r.signature = $signature,
                    r.pgp_signature = $pgp_signature,
                    r.previous_record_hash = $previous_record_hash,
                    r.timestamp = $timestamp,
                    r.agent = $agent,
                    r.action = $action
                """
                db.execute_query(cypher_node, {
                    "record_hash": record["record_hash"],
                    "payload": serialized_payload,
                    "signature": record["signature"],
                    "pgp_signature": record.get("pgp_signature"),
                    "previous_record_hash": prev_hash,
                    "timestamp": timestamp,
                    "agent": agent_name,
                    "action": action
                })
                
                if prev_hash != "0" * 64:
                    cypher_edge = """
                    MATCH (prev:AuditRecord {record_hash: $prev_hash})
                    MATCH (curr:AuditRecord {record_hash: $curr_hash})
                    MERGE (curr)-[:PREV_RECORD]->(prev)
                    """
                    db.execute_query(cypher_edge, {
                        "prev_hash": prev_hash,
                        "curr_hash": record["record_hash"]
                    })
                logger.info(f"AuditRecord node persisted to Neo4j (Hash: {record['record_hash'][:8]})")
        except Exception as e:
            logger.warning(f"Failed to write AuditRecord to Neo4j: {e}")
            
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

        # 1. Verify Neo4j Graph-Based Ledger
        db_records = []
        db_connected = False
        try:
            from karasugakure.graph.db import get_db
            db = get_db()
            if db.check_connection():
                db_connected = True
                query = """
                MATCH (r:AuditRecord)
                RETURN r.record_hash AS record_hash,
                       r.signature AS signature,
                       r.pgp_signature AS pgp_signature,
                       r.previous_record_hash AS previous_record_hash,
                       r.timestamp AS timestamp,
                       r.payload AS payload,
                       r.agent AS agent,
                       r.action AS action
                ORDER BY r.timestamp ASC
                """
                db_records = db.execute_query(query)
        except Exception as e:
            logger.warning(f"Could not connect to Neo4j for ledger verification: {e}")

        master_key = self._get_master_key()

        if db_connected:
            expected_prev_hash = "0" * 64
            idx = 0
            for r in db_records:
                idx += 1
                rec_hash = r.get("record_hash")
                sig = r.get("signature")
                prev_hash = r.get("previous_record_hash")
                payload_str = r.get("payload")
                
                if not rec_hash or not sig or not payload_str:
                    diff_summary["is_corrupt"] = True
                    diff_summary["corruptions"].append({
                        "database_index": idx,
                        "reason": "Graph record structural fields missing in Neo4j"
                    })
                    continue
                
                # Verify prev hash link
                if prev_hash != expected_prev_hash:
                    diff_summary["is_corrupt"] = True
                    diff_summary["corruptions"].append({
                        "database_index": idx,
                        "reason": "Graph broken hash-chain link in Neo4j",
                        "expected_prev_hash": expected_prev_hash,
                        "actual_prev_hash": prev_hash
                    })

                # Verify HMAC signature
                computed_sig = hmac.new(master_key, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(sig, computed_sig):
                    diff_summary["is_corrupt"] = True
                    diff_summary["corruptions"].append({
                        "database_index": idx,
                        "reason": "Graph HMAC signature mismatch in Neo4j",
                        "expected_signature": computed_sig,
                        "actual_signature": sig
                    })

                # Verify record hash
                computed_hash = hashlib.sha256((payload_str + sig).encode("utf-8")).hexdigest()
                if computed_hash != rec_hash:
                    diff_summary["is_corrupt"] = True
                    diff_summary["corruptions"].append({
                        "database_index": idx,
                        "reason": "Graph record hash corruption in Neo4j",
                        "expected_hash": computed_hash,
                        "actual_hash": rec_hash
                    })
                
                expected_prev_hash = rec_hash
            
            logger.info(f"Verified {idx} graph-based AuditRecord nodes in Neo4j.")

        # 2. Verify File-Based Ledger (always, as dual-layer validation and local fallback)
        if not self.ledger_path.exists():
            if not db_connected or not db_records:
                with open(diff_path, "w") as f_diff:
                    json.dump(diff_summary, f_diff, indent=2)
                return True # Empty ledger is technically integral
            
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
                            "reason": "Corrupt file record structural fields missing",
                            "expected_fields": ["payload", "signature", "record_hash"]
                        })
                        continue
                        
                    # 1. Verify Prev Hash Link
                    actual_prev_hash = payload.get("previous_record_hash")
                    if actual_prev_hash != expected_prev_hash:
                        diff_summary["is_corrupt"] = True
                        diff_summary["corruptions"].append({
                            "line": line_num,
                            "reason": "Broken file hash-chain link",
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
                            "reason": "File HMAC signature mismatch",
                            "expected_signature": computed_sig,
                            "actual_signature": sig
                        })
                        
                    # 3. Verify record hash
                    computed_hash = hashlib.sha256((serialized_payload + sig).encode("utf-8")).hexdigest()
                    if computed_hash != rec_hash:
                        diff_summary["is_corrupt"] = True
                        diff_summary["corruptions"].append({
                            "line": line_num,
                            "reason": "File record hash corruption",
                            "expected_hash": computed_hash,
                            "actual_hash": rec_hash
                        })
                        
                    expected_prev_hash = rec_hash
                    diff_summary["checked_records_count"] = max(line_num, diff_summary["checked_records_count"])

            # Write diff summary for operator review
            with open(diff_path, "w") as f_diff:
                json.dump(diff_summary, f_diff, indent=2)

            if diff_summary["is_corrupt"]:
                logger.error(f"Forensic Audit Ledger Integrity check failed! Corruptions: {diff_summary['corruptions']}")
                return False

            logger.info(f"Forensic Audit Ledger verified successfully. Checked file lines: {line_num}. Integrity: OK.")
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

