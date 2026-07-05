import random
import requests
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from karasugakure.config import get_config

logger = logging.getLogger("karasugakure.utils.net")

# Default user agents list in case rotation config file is missing
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0"
]

def get_rotated_user_agent() -> str:
    """Loads a random user agent from opsec/ua_rotation.json if available, else defaults."""
    config = get_config()
    ua_file = config.base_dir / "opsec" / "ua_rotation.json"
    if ua_file.exists():
        try:
            with open(ua_file, "r") as f:
                uas = json.load(f)
                if isinstance(uas, list) and uas:
                    return random.choice(uas)
        except Exception as e:
            logger.warning(f"Failed to read user agents from {ua_file}: {e}")
    return random.choice(DEFAULT_USER_AGENTS)

def make_tor_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Any] = None,
    json_data: Optional[Any] = None,
    timeout: float = 10.0,
    force_tor: bool = False,
    agent_name: Optional[str] = None
) -> requests.Response:
    """
    Sends an HTTP request with OPSEC headers (e.g. user-agent rotation)
    and routes traffic via Tor SOCKS5 proxy if specified by configuration or forced.
    Enforces route validation before dispatch.
    """
    from karasugakure.policy.opsec import verify_network_route, get_active_proxies
    verify_network_route(url, agent_name=agent_name, force_tor=force_tor)

    config = get_config()
    proxies = {}
    
    # Check if Tor proxy is enabled in config or forced (e.g. Hel agent)
    if force_tor or config.opsec.tor_proxy:
        from karasugakure.daemons.isolator import isolator
        isolator.rotate_identity() # OPSEC: Rotate circuit per-request
        
        active_proxies = get_active_proxies()
        if active_proxies:
            proxy_url = random.choice(active_proxies)
            proxies = {
                "http": proxy_url,
                "https": proxy_url
            }
            logger.debug(f"Routing request through rotated Tor proxy: {proxy_url}")
        else:
            proxy_url = config.opsec.tor_proxy or "socks5h://127.0.0.1:9050"
            proxies = {
                "http": proxy_url,
                "https": proxy_url
            }
            logger.warning(f"No active proxies in pool. Falling back to default Tor proxy: {proxy_url}")
        
    req_headers = headers or {}
    if config.opsec.user_agent_rotation and "User-Agent" not in req_headers:
        req_headers["User-Agent"] = get_rotated_user_agent()
        
    # Standard security headers to avoid finger printing
    if "Accept-Language" not in req_headers:
        req_headers["Accept-Language"] = "en-US,en;q=0.9"
        
    # OPSEC Jitter: Exponential delay to mimic human behavior and evade WAF rate limits
    # Mean delay of 2.5 seconds, capped at 6.0 seconds.
    import time
    delay = random.expovariate(1.0 / 2.5)
    delay = min(delay, 6.0)
    if delay > 0:
        logger.debug(f"[OPSEC-JITTER] Aplicando retraso exponencial de {delay:.2f}s antes del request HTTP/S...")
        time.sleep(delay)
        
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=req_headers,
            data=data,
            json=json_data,
            proxies=proxies,
            timeout=timeout
        )
        return response
    except Exception as e:
        logger.error(f"Network request failed for {url}: {e}")
        raise e
