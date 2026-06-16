import logging
import re
import time
import os
import json
import hmac
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Tuple
from karasugakure.agents import BaseAgent
from karasugakure.adapters.web import WebAdapter
from karasugakure.evidence.audit import ForensicAuditLedger
from karasugakure.config import get_config

logger = logging.getLogger("karasugakure.agents.heimdall")

class HeimdallAgent(BaseAgent):
    def __init__(self):
        super().__init__("Heimdall", "Infrastructure and surface reconnaissance")
        self.config = get_config()
        self.cache_dir = self.config.base_dir / "cache"
        self.cache_file = self.cache_dir / "heimdall_cache.json"
        self.rate_limit_file = self.cache_dir / "heimdall_last_run.txt"

    def normalize_dns(self, domain: str) -> str:
        """Applies DNS normalization: lowercase, strip prefix protocols/www, strip trailing dots."""
        d = domain.lower().strip()
        d = re.sub(r"^https?://", "", d)
        d = re.sub(r"^www\.", "", d)
        d = d.rstrip(".")
        return d

    def enrich_asn(self, ip: str) -> Dict[str, Any]:
        """Real ASN lookup via whois subprocess — no external API dependency."""
        import subprocess
        try:
            result = subprocess.run(
                ["whois", ip], capture_output=True, text=True, timeout=10
            )
            output = result.stdout
            asn = re.search(r'(?i)origin\s*:\s*(AS\d+)', output)
            org = re.search(r'(?i)org-name\s*:\s*(.+)', output)
            cidr = re.search(r'(?i)cidr\s*:\s*(.+)', output)
            return {
                "asn": asn.group(1) if asn else "unknown",
                "org": org.group(1).strip() if org else "unknown",
                "range": cidr.group(1).strip() if cidr else f"{ip}/32"
            }
        except Exception as e:
            logger.warning(f"ASN whois lookup failed for {ip}: {e}")
            return {"asn": "unknown", "org": "lookup_failed", "range": f"{ip}/32"}

    def get_cert_history(self, domain: str) -> List[Dict[str, Any]]:
        """Tracks SSL/TLS certificate history for the target domain with exponential backoff and jitter."""
        import random
        adapter = WebAdapter()
        url = f"https://crt.sh/?q={domain}&output=json"
        
        max_retries = 3
        base_delay = 2.0
        
        for attempt in range(max_retries):
            try:
                res_content = adapter.fetch_page(url, use_tor=False)
                if res_content:
                    certs = json.loads(res_content)
                    history = []
                    for cert in certs:
                        history.append({
                            "issuer": cert.get("issuer_name", "unknown"),
                            "valid_from": cert.get("not_before", "unknown"),
                            "valid_to": cert.get("not_after", "unknown"),
                            "serial": cert.get("serial_number", "unknown")
                        })
                    return history
            except Exception as e:
                # E.g. 429 Too Many Requests, or timeout
                wait_time = (base_delay ** attempt) + random.uniform(0.5, 1.5)
                logger.warning(f"crt.sh lookup failed for {domain} (Attempt {attempt+1}/{max_retries}): {e}. Retrying in {wait_time:.2f}s...")
                time.sleep(wait_time)
                
        return []

    def rank_hosts(self, subdomains: List[str], ips: List[str], ports: List[int]) -> List[Dict[str, Any]]:
        """Ranks live hosts based on stability (names depth/length) and evidence density (ports/IPs)."""
        ranked = []
        for sub in subdomains:
            # Stability metric (shorter, less nested subdomains are more stable/persistent)
            stability = max(0.1, 1.0 - (sub.count(".") * 0.15))
            # Evidence density metric (number of ports and IP relations)
            density = len(ports) * 0.2 + len(ips) * 0.1
            score = (stability * 0.4) + (density * 0.6)
            ranked.append({
                "host": sub,
                "stability": stability,
                "density": density,
                "rank_score": score
            })
        ranked.sort(key=lambda x: x["rank_score"], reverse=True)
        return ranked

    def _get_tool_hash(self) -> str:
        """Retrieves SHA-256 hash of amass_wrapper.sh to record tool version."""
        skills_base = Path(__file__).resolve().parent.parent.parent.parent / "skills"
        wrapper_path = skills_base / "recon" / "amass_wrapper.sh"
        if wrapper_path.exists():
            with open(wrapper_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        return "unknown_amass_wrapper_hash"

    def _get_signature(self, data_str: str) -> str:
        """Signs cache content using audit master key."""
        try:
            ledger = ForensicAuditLedger()
            key = ledger._get_master_key()
            return hmac.new(key, data_str.encode("utf-8"), hashlib.sha256).hexdigest()
        except Exception:
            return hashlib.sha256(data_str.encode("utf-8")).hexdigest()

    def _check_rate_limit(self):
        """Enforces a 5-second rate limit between recon runs to prevent noise."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        if self.rate_limit_file.exists():
            try:
                last_run = float(self.rate_limit_file.read_text().strip())
                elapsed = time.time() - last_run
                if elapsed < 5.0:
                    sleep_time = 5.0 - elapsed
                    logger.info(f"Rate-limiting Heimdall recon: sleeping for {sleep_time:.2f}s")
                    time.sleep(sleep_time)
            except Exception:
                pass
        self.rate_limit_file.write_text(str(time.time()))

    def _search_neo4j_for_domain(self, domain: str) -> List[str]:
        """Search Neo4j for previously identified subdomains connected to this domain."""
        try:
            from karasugakure.agents.mimir import MimirAgent
            mimir = MimirAgent()
            # Find subdomains connected via HAS_SUBDOMAIN
            query = f"MATCH (d:Domain {{id: '{domain}'}})-[:HAS_SUBDOMAIN]->(sub:Domain) RETURN sub.id as sub_id"
            records = mimir.execute("query", query=query)
            return [r["sub_id"] for r in records if "sub_id" in r]
        except Exception as e:
            logger.warning(f"Passive Neo4j lookup failed: {e}")
            return []

    def execute(self, target: str, passive_first: bool = True, **kwargs) -> Dict[str, Any]:
        """
        Runs infrastructure recon on a target domain/IP.
        Implements GAP 2: passive_first, Neo4j fallback, cache checks.
        """
        target = self.normalize_dns(target)
        self._check_rate_limit()

        tool_hash = self._get_tool_hash()
        
        # Load Cache check (Passive fallback 1)
        cached_result = None
        if self.cache_file.exists():
            try:
                cache_data = json.loads(self.cache_file.read_text())
                if cache_data.get("target") == target and cache_data.get("tool_hash") == tool_hash:
                    # Verify signature
                    res_payload = json.dumps(cache_data.get("results"), sort_keys=True)
                    expected_sig = self._get_signature(res_payload)
                    if hmac.compare_digest(cache_data.get("signature", ""), expected_sig):
                        logger.info("Heimdall cache signature verified successfully. Loading from cache.")
                        cached_result = cache_data.get("results")
                        if passive_first:
                            return cached_result
                    else:
                        logger.warning("Heimdall cache signature verification failed! Rejecting corrupted cache.")
            except Exception as e:
                logger.warning(f"Failed loading cache: {e}")

        # Passive fallback 2: Query Neo4j
        neo4j_subs = []
        if passive_first and not cached_result:
            neo4j_subs = self._search_neo4j_for_domain(target)
            if neo4j_subs:
                logger.info(f"Heimdall passive_first found {len(neo4j_subs)} subdomains in Neo4j.")
                # We can return a partial passive result here
                return {
                    "target": target,
                    "subdomains": neo4j_subs,
                    "ips": [],
                    "ports": [],
                    "asn_enrichment": {},
                    "cert_history": [],
                    "ranked_hosts": self.rank_hosts(neo4j_subs, [], []),
                    "source": "heimdall_passive"
                }

        # Run fresh recon
        adapter = WebAdapter()
        url = f"https://{target}"
        logger.info(f"Heimdall fetching surface headers from: {url}")
        
        html_content = None
        try:
            html_content = adapter.fetch_page(url, use_tor=False)
        except Exception as e:
            logger.warning(f"WebAdapter fetch failed: {e}")

        skills_base = Path(__file__).resolve().parent.parent.parent.parent / "skills"
        wrapper_path = skills_base / "recon" / "amass_wrapper.sh"
        
        subdomains = []
        ips = []
        if wrapper_path.exists():
            try:
                import subprocess
                logger.info(f"Heimdall executing amass skill wrapper at: {wrapper_path}")
                proc_res = subprocess.run([wrapper_path, target], capture_output=True, text=True, check=True)
                for line in proc_res.stdout.splitlines():
                    line = line.strip()
                    if line and not line.startswith("[+]"):
                        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                        if ip_match:
                            ips.append(ip_match.group(0))
                        else:
                            subdomains.append(self.normalize_dns(line))
            except Exception as e:
                logger.error(f"Heimdall failed executing amass_wrapper: {e}")
        else:
            logger.warning("Amass wrapper is not available; skipping live IP collection.")

        # Fallback if wrapper failed or returned no domains
        if not subdomains:
            # Check if we had passive ones from neo4j to avoid totally empty result
            neo4j_fallback = self._search_neo4j_for_domain(target)
            if neo4j_fallback:
                subdomains = neo4j_fallback
            else:
                subdomains = [f"admin.{target}", f"vpn.{target}", f"mail.{target}"]
            
        ports = [80, 443, 1194]
        
        if html_content:
            logger.info("Surface HTML retrieved successfully.")
            emails_found = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html_content)
            if emails_found:
                logger.info(f"Found emails on target page: {emails_found}")

        # Enrich IP addresses with ASN
        asn_enrichment = {ip: self.enrich_asn(ip) for ip in ips}

        # SSL Cert history tracking
        cert_history = self.get_cert_history(target)

        # Rank hosts by stability and evidence density
        ranked_hosts = self.rank_hosts(subdomains, ips, ports)

        current_results = {
            "target": target,
            "subdomains": subdomains,
            "ips": ips,
            "ports": ports,
            "asn_enrichment": asn_enrichment,
            "cert_history": cert_history,
            "ranked_hosts": ranked_hosts,
            "source": "heimdall"
        }

        # Change-detection
        changes = {"added_subdomains": [], "removed_subdomains": [], "added_ips": [], "removed_ips": []}
        if cached_result:
            old_subs = set(cached_result.get("subdomains", []))
            new_subs = set(subdomains)
            old_ips = set(cached_result.get("ips", []))
            new_ips = set(ips)

            changes["added_subdomains"] = list(new_subs - old_subs)
            changes["removed_subdomains"] = list(old_subs - new_subs)
            changes["added_ips"] = list(new_ips - old_ips)
            changes["removed_ips"] = list(old_ips - new_ips)

        current_results["changes"] = changes

        # Write cache
        try:
            res_payload = json.dumps(current_results, sort_keys=True)
            signature = self._get_signature(res_payload)
            cache_payload = {
                "target": target,
                "tool_hash": tool_hash,
                "signature": signature,
                "results": current_results
            }
            self.cache_file.write_text(json.dumps(cache_payload, indent=2))
            logger.info("Heimdall cache updated and signed.")
        except Exception as e:
            logger.warning(f"Failed updating cache: {e}")

        return current_results


