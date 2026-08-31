import socket
import logging
import sys
import os
from multiprocessing import Process, Queue
from typing import Callable, Any, Dict, Optional

logger = logging.getLogger("amegakurewotan.policy.opsec")

class OPSECViolationException(Exception):
    """Raised when an OPSEC guardrail is violated."""
    pass

def check_tor_socks_proxy(host: str = "127.0.0.1", port: int = 9050) -> bool:
    """Checks if the SOCKS Tor proxy is up and accepting connections."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((host, port))
        s.close()
        return True
    except Exception as e:
        logger.warning(f"Tor SOCKS proxy on {host}:{port} is down: {e}")
        return False

def enforce_opsec_policy(agent_name: str, config=None):
    """
    Enforces strict network and environment policy for agents.
    If agent_name is 'hel' or 'loki', ensures Tor proxy is active unless bypass is set.
    """
    agent_lower = agent_name.lower()
    bypass_tor = os.environ.get("AMEWOTAN_OPSEC_BYPASS_TOR", "false").lower() == "true"
    if bypass_tor:
        logger.debug(f"[OPSEC-BYPASS] Tor check OMITIDO para '{agent_name}'.")
        return
    
    if agent_lower in ["hel", "loki"]:
        tor_host = "127.0.0.1"
        tor_port = 9050
        if config and hasattr(config, "opsec") and config.opsec.tor_proxy:
            try:
                parts = config.opsec.tor_proxy.split("://")[-1].split(":")
                tor_host = parts[0]
                tor_port = int(parts[1])
            except Exception:
                pass
        
        if not check_tor_socks_proxy(tor_host, tor_port):
            msg = f"CRITICAL OPSEC ALARM: Tor proxy is unreachable at {tor_host}:{tor_port}!"
            raise OPSECViolationException(msg)


def get_active_proxies() -> list[str]:
    """Returns a list of reachable proxies from the configured pool."""
    from amegakurewotan.config import get_config
    config = get_config()
    proxy_pool_str = os.environ.get("OPSEC_TOR_PROXY_POOL") or getattr(config.opsec, "tor_proxy_pool", None) or config.opsec.tor_proxy
    if not proxy_pool_str:
        return []
    
    pool = [p.strip() for p in proxy_pool_str.split(",") if p.strip()]
    active = []
    for proxy_url in pool:
        tor_host = "127.0.0.1"
        tor_port = 9050
        try:
            parts = proxy_url.split("://")[-1].split(":")
            tor_host = parts[0]
            tor_port = int(parts[1])
        except Exception:
            pass
        if check_tor_socks_proxy(tor_host, tor_port):
            active.append(proxy_url)
    return active

def verify_network_route(url: str, agent_name: Optional[str] = None, force_tor: bool = False):
    """
    Enforces route checks before network actions.
    """
    agent_clean = agent_name.lower() if agent_name else None
    is_onion = url.strip().lower().endswith(".onion") or ".onion/" in url.lower()
    is_sensitive = agent_clean in ["hel", "loki"]
    
    if force_tor or is_onion or is_sensitive:
        active_proxies = get_active_proxies()
        if not active_proxies:
            raise OPSECViolationException(
                f"OPSEC VIOLATION: Request to '{url}' requires Tor proxy, but all proxies in the pool are offline."
            )


def run_isolated_process(func: Callable, *args, **kwargs) -> Any:
    """
    Runs a function in an isolated process to protect memory without scrubbing credentials.
    """
    def worker(q: Queue, f: Callable, a: tuple, kw: dict):
        try:
            res = f(*a, **kw)
            q.put((True, res))
        except Exception as e:
            q.put((False, e))
        finally:
            import gc
            import sys
            try:
                sys.stdout.flush()
                sys.stderr.flush()
            except Exception:
                pass
            gc.collect()

    q = Queue()
    p = Process(target=worker, args=(q, func, args, kwargs))
    
    ISOLATION_TIMEOUT = int(os.environ.get("AMEWOTAN_ISOLATION_TIMEOUT", "120"))

    p.start()
    p.join(timeout=ISOLATION_TIMEOUT)

    if p.is_alive():
        p.terminate()
        p.join(timeout=5)
        if p.is_alive():
            p.kill()
        raise TimeoutError(f"Isolated process killed after {ISOLATION_TIMEOUT}s timeout.")
    
    if q.empty():
        raise RuntimeError("Isolated process terminated unexpectedly without returning a result.")
    
    success, value = q.get()
    if success:
        return value
    else:
        raise value




