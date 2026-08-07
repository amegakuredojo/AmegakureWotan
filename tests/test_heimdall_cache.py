import pytest
import json
import hmac
import hashlib
from pathlib import Path
from unittest.mock import patch, MagicMock
from amegakurewotan.agents.heimdall import HeimdallAgent
from amegakurewotan.config import get_config

@pytest.fixture(autouse=True)
def mock_config_base_dir(tmp_path, monkeypatch):
    config = get_config()
    monkeypatch.setattr(config, "base_dir", tmp_path)
    config.init_dirs()

def test_heimdall_cache_verification(tmp_path):
    """Verify HeimdallAgent loads from valid cache and rejects corrupted/tampered cache."""
    agent = HeimdallAgent()
    target = "testcachetarget.com"
    
    # 1. Prepare valid cache results
    cached_results = {
        "target": target,
        "subdomains": [f"admin.{target}"],
        "ips": [],
        "ports": [80],
        "asn_enrichment": {},
        "cert_history": [],
        "ranked_hosts": [],
        "source": "heimdall",
        "changes": {"added_subdomains": [], "removed_subdomains": [], "added_ips": [], "removed_ips": []}
    }
    
    # Compute signature
    res_payload = json.dumps(cached_results, sort_keys=True)
    signature = agent._get_signature(res_payload)
    
    cache_payload = {
        "target": target,
        "tool_hash": agent._get_tool_hash(),
        "signature": signature,
        "results": cached_results
    }
    
    # Write to cache file
    agent.cache_dir.mkdir(parents=True, exist_ok=True)
    agent.cache_file.write_text(json.dumps(cache_payload, indent=2))
    
    # Execute with valid cache
    with patch("amegakurewotan.adapters.web.WebAdapter.fetch_page", return_value=None):
        res = agent.execute(target)
        assert res["subdomains"] == [f"admin.{target}"]
        assert res["source"] == "heimdall"
        
    # 2. Corrupt cache results (tampering)
    cached_results["subdomains"] = [f"corrupted.{target}"]
    corrupted_payload = {
        "target": target,
        "tool_hash": agent._get_tool_hash(),
        "signature": signature,  # old signature
        "results": cached_results
    }
    agent.cache_file.write_text(json.dumps(corrupted_payload, indent=2))
    
    # Execute with corrupted cache
    dummy_html = "<html>fresh</html>"
    with patch("amegakurewotan.adapters.web.WebAdapter.fetch_page", return_value=dummy_html), \
         patch("subprocess.run") as mock_subproc:
         
        # Mock amass wrapper not being run
        mock_subproc.side_effect = Exception("Not available")
        res = agent.execute(target)
        
        # It should run fresh fallback and return fallback subdomains admin.vpn.mail instead of the corrupted one
        assert f"corrupted.{target}" not in res["subdomains"]
        assert f"admin.{target}" in res["subdomains"]
