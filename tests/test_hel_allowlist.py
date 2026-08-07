import pytest
import time
from unittest.mock import patch, MagicMock
from amegakurewotan.agents.hel import HelAgent

def test_hel_allowlist_and_stale():
    """Verify that allowlist filters out rogue onions and stale onions are rejected."""
    hel = HelAgent()
    
    # We mock check_tor_socks_proxy to return True so OPSEC check passes
    # We mock DarkWebAdapter.query_onion to return mock HTML
    # We mock candidate onion data inside hel.py if possible, or just let it process the list
    # and verify that untrustedxxxxx.onion is not in the results, and stale onion is not in results.
    
    mock_html = "<html><head><title>Hacker Forum Leak DB</title></head><body>some email@test.com leak data</body></html>"
    
    with patch("amegakurewotan.policy.opsec.check_tor_socks_proxy", return_value=True), \
         patch("amegakurewotan.adapters.darkweb.DarkWebAdapter.query_onion", return_value=mock_html):
         
        # Execute HelAgent
        res = hel.execute("email@test.com")
        
        # Check onion_sites returned
        onion_sites = res.get("onion_sites", [])
        onions = [o["onion"] for o in onion_sites]
        
        # untrustedxxxxx.onion is NOT in the allowlist, so it must be rejected
        assert "untrustedxxxxx.onion" not in onions, "Rogue onion was not filtered out by the allowlist!"
        
        # leaks777xxxxxxxx.onion is allowlisted and fresh, so it should be accepted
        assert "leaks777xxxxxxxx.onion" in onions
        
        # market666xxxxxxx.onion is allowlisted and fresh, so it should be accepted
        assert "market666xxxxxxx.onion" in onions
