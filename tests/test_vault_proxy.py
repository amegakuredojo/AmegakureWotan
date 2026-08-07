import pytest
import json
import os
import random
from unittest.mock import patch, MagicMock
from pathlib import Path
from amegakurewotan.config import get_config
from amegakurewotan.policy.vault import CredentialVault
from amegakurewotan.policy.opsec import get_active_proxies, verify_network_route
from amegakurewotan.utils.net import make_tor_request

@pytest.fixture(autouse=True)
def mock_config_base_dir(tmp_path, monkeypatch):
    config = get_config()
    monkeypatch.setattr(config, "base_dir", tmp_path)
    config.init_dirs()

def test_credential_vault_flow():
    """Verify that CredentialVault can store, retrieve, list, and delete credentials securely using GPG."""
    vault = CredentialVault()
    
    # 1. Initially empty
    assert vault.list_credentials() == {}
    
    # 2. Store keys
    vault.set_credential("shodan", "shodan_secret_key_123")
    vault.set_credential("censys", "censys_secret_key_456")
    
    # 3. Retrieve keys
    assert vault.get_credential("shodan") == "shodan_secret_key_123"
    assert vault.get_credential("censys") == "censys_secret_key_456"
    assert vault.get_credential("unknown") is None
    
    # 4. Check listing
    creds = vault.list_credentials()
    assert len(creds) == 2
    assert creds["shodan"] == "shodan_secret_key_123"
    assert creds["censys"] == "censys_secret_key_456"
    
    # 5. Delete key
    vault.delete_credential("shodan")
    assert vault.get_credential("shodan") is None
    assert vault.get_credential("censys") == "censys_secret_key_456"

def test_get_active_proxies_filtering():
    """Verify that get_active_proxies filters out unreachable proxies from the pool."""
    config = get_config()
    # Configure a pool of three proxies
    pool = "socks5h://127.0.0.1:9050,socks5h://127.0.0.1:9051,socks5h://127.0.0.1:9052"
    config.opsec.tor_proxy_pool = pool
    
    # Mock check_tor_socks_proxy: 9050 and 9052 are online, 9051 is offline
    def mock_check(host, port):
        if port in [9050, 9052]:
            return True
        return False
        
    with patch("amegakurewotan.policy.opsec.check_tor_socks_proxy", side_effect=mock_check):
        active = get_active_proxies()
        assert len(active) == 2
        assert "socks5h://127.0.0.1:9050" in active
        assert "socks5h://127.0.0.1:9052" in active
        assert "socks5h://127.0.0.1:9051" not in active

def test_make_tor_request_rotation():
    """Verify that make_tor_request rotates requests randomly using only online proxies from the pool."""
    config = get_config()
    pool = "socks5h://127.0.0.1:9050,socks5h://127.0.0.1:9051"
    config.opsec.tor_proxy_pool = pool
    
    # Mock both proxies as online. Also neutralize the OPSEC jitter sleep and the
    # Tor circuit rotation so the 20-iteration rotation check is hermetic and fast
    # (otherwise random.expovariate jitter sleeps up to 6s per request => test hangs).
    with patch("amegakurewotan.policy.opsec.check_tor_socks_proxy", return_value=True), \
         patch("amegakurewotan.utils.net.time.sleep", return_value=None), \
         patch("amegakurewotan.daemons.isolator.isolator.rotate_identity", return_value=None), \
         patch("requests.request") as mock_req:
         
        mock_req.return_value = MagicMock(status_code=200, text="success")
        
        used_proxies = set()
        # Perform multiple requests to verify rotation selection
        for _ in range(20):
            make_tor_request("http://testtarget.onion", force_tor=True, agent_name="hel")
            # Extract proxy parameter passed to requests.request
            args, kwargs = mock_req.call_args
            proxy_url = kwargs.get("proxies", {}).get("http")
            assert proxy_url is not None
            used_proxies.add(proxy_url)
            
        # Verify that both proxies in the pool were chosen/rotated
        assert len(used_proxies) == 2
        assert "socks5h://127.0.0.1:9050" in used_proxies
        assert "socks5h://127.0.0.1:9051" in used_proxies
