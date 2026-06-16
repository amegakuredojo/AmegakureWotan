import pytest
from unittest.mock import patch
from karasugakure.policy.opsec import enforce_opsec_policy, OPSECViolationException
from karasugakure.config import get_config

def test_opsec_policy_tor_down():
    """Verify that if Tor proxy check fails, enforce_opsec_policy raises OPSECViolationException."""
    config = get_config()
    
    # Mock check_tor_socks_proxy to return False
    with patch("karasugakure.policy.opsec.check_tor_socks_proxy", return_value=False):
        with pytest.raises(OPSECViolationException) as excinfo:
            enforce_opsec_policy("hel", config)
        assert "explicitly denied direct clear-web access" in str(excinfo.value) or "Tor socks proxy is not active" in str(excinfo.value) or "Tor proxy is unreachable" in str(excinfo.value)
