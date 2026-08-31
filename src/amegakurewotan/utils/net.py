import random
import requests
import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional
from amegakurewotan.config import get_config

logger = logging.getLogger("amegakurewotan.utils.net")

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

def make_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Any] = None,
    json_data: Optional[Any] = None,
    timeout: float = 15.0,
    force_tor: bool = False,
    agent_name: Optional[str] = None
) -> requests.Response:
    """
    Sends a clean, resilient HTTP/S request.
    Uses direct network connection by default, with proxy routing only if explicitly configured.
    """
    from amegakurewotan.policy.opsec import verify_network_route, get_active_proxies
    verify_network_route(url, agent_name=agent_name, force_tor=force_tor)

    config = get_config()
    proxies = {}
    
    # Optional proxy routing if explicitly provided in configuration
    if config.opsec.tor_proxy or force_tor:
        active_proxies = get_active_proxies()
        if active_proxies:
            proxy_url = random.choice(active_proxies)
            proxies = {"http": proxy_url, "https": proxy_url}
        elif config.opsec.tor_proxy:
            proxies = {"http": config.opsec.tor_proxy, "https": config.opsec.tor_proxy}
        
    req_headers = headers or {}
    if getattr(config.opsec, "user_agent_rotation", True) and "User-Agent" not in req_headers:
        req_headers["User-Agent"] = get_rotated_user_agent()
        
    if "Accept-Language" not in req_headers:
        req_headers["Accept-Language"] = "en-US,en;q=0.9"
        
    # Rate limit suave si está habilitado
    try:
        from amegakurewotan.utils.ratelimit import get_rate_limiter
        get_rate_limiter().acquire()
    except Exception:
        pass

    # Jitter opcional solo si está explícitamente activado
    if getattr(config.opsec, "enable_jitter", False):
        delay = min(random.expovariate(1.0 / 2.5), 6.0)
        if delay > 0:
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
        logger.warning(f"Network request to {url} encountered an issue: {e}")
        raise e

def make_tor_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Any] = None,
    json_data: Optional[Any] = None,
    timeout: float = 15.0,
    force_tor: bool = False,
    agent_name: Optional[str] = None
) -> requests.Response:
    """Retrocompatible alias for make_request."""
    return make_request(
        url=url,
        method=method,
        headers=headers,
        data=data,
        json_data=json_data,
        timeout=timeout,
        force_tor=force_tor,
        agent_name=agent_name
    )
