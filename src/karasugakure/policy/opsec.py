import socket
import logging
import sys
import os
from multiprocessing import Process, Queue
from typing import Callable, Any, Dict, Optional

logger = logging.getLogger("karasugakure.policy.opsec")

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
    If agent_name is 'hel' or 'loki', ensures Tor proxy is active.
    Raises OPSECViolationException if the environment is unsafe.
    """
    agent_lower = agent_name.lower()
    if agent_lower in ["hel", "loki"]:
        # Tor proxy must be reachable
        tor_host = "127.0.0.1"
        tor_port = 9050
        if config and hasattr(config, "opsec") and config.opsec.tor_proxy:
            try:
                parts = config.opsec.tor_proxy.split("://")[-1].split(":")
                tor_host = parts[0]
                tor_port = int(parts[1])
            except Exception:
                pass
        
        logger.info(f"Enforcing OPSEC for network agent '{agent_name}' against Tor proxy {tor_host}:{tor_port}...")
        if not check_tor_socks_proxy(tor_host, tor_port):
            msg = f"CRITICAL OPSEC ALARM: Tor proxy is unreachable at {tor_host}:{tor_port}! Execution of '{agent_name}' agent is BLOCKED to prevent traffic leaks."
            logger.error(msg)
            raise OPSECViolationException(msg)
        
        logger.info(f"OPSEC check passed for '{agent_name}': Tor proxy is active.")

def verify_network_route(url: str, agent_name: Optional[str] = None, force_tor: bool = False):
    """
    Enforces route checks before every network action.
    Maintains agent-specific routing policies and explicit clear-web denial for sensitive agents.
    """
    from karasugakure.config import get_config
    config = get_config()
    
    agent_clean = agent_name.lower() if agent_name else None
    is_onion = url.strip().lower().endswith(".onion") or ".onion/" in url.lower()
    is_sensitive = agent_clean in ["hel", "loki"]
    
    # 1. Enforce Tor routing checks for onion or forced tor or sensitive agents
    if force_tor or is_onion or is_sensitive:
        if not config.opsec.tor_proxy:
            raise OPSECViolationException(
                f"OPSEC VIOLATION: Request to '{url}' requires Tor proxy, but config.opsec.tor_proxy is empty."
            )
            
        tor_host = "127.0.0.1"
        tor_port = 9050
        try:
            parts = config.opsec.tor_proxy.split("://")[-1].split(":")
            tor_host = parts[0]
            tor_port = int(parts[1])
        except Exception:
            pass
            
        if not check_tor_socks_proxy(tor_host, tor_port):
            raise OPSECViolationException(
                f"OPSEC VIOLATION: Tor SOCKS proxy is offline ({tor_host}:{tor_port}). Blocked request to '{url}'."
            )

    # 2. Explicit clear-web direct access denial for sensitive agents
    if is_sensitive and not force_tor and not is_onion:
        # Sensitive agents are blocked from clear-web direct routing without Tor
        if not config.opsec.tor_proxy:
            raise OPSECViolationException(
                f"OPSEC VIOLATION: Sensitive agent '{agent_name}' is explicitly denied direct clear-web access."
            )

def run_isolated_process(func: Callable, *args, **kwargs) -> Any:
    """
    Runs a function in an isolated process to protect credentials and memory.
    Scrubs sensitive environment variables and flushes memory buffers.
    """
    def worker(q: Queue, f: Callable, a: tuple, kw: dict):
        try:
            # Clear sensitive env variables in child process memory before executing
            for key in list(os.environ.keys()):
                if any(x in key.upper() for x in ["SECRET", "PASSWORD", "AUTH", "KEY", "TOKEN", "CREDENTIAL"]):
                    del os.environ[key]

            res = f(*a, **kw)
            q.put((True, res))
        except Exception as e:
            q.put((False, e))
        finally:
            # Explicit cleanup of child process footprints
            import gc
            import sys
            # Flush stdout and stderr
            try:
                sys.stdout.flush()
                sys.stderr.flush()
            except Exception:
                pass
            # Clear any remaining environment variables
            for key in list(os.environ.keys()):
                if any(x in key.upper() for x in ["NEO4J", "SECRET", "PASSWORD", "AUTH", "KEY"]):
                    del os.environ[key]
            # Run garbage collector to clear memory structures
            gc.collect()

    q = Queue()
    p = Process(target=worker, args=(q, func, args, kwargs))
    
    ISOLATION_TIMEOUT = int(os.environ.get("KARASU_ISOLATION_TIMEOUT", "120"))  # 2 min default

    p.start()
    p.join(timeout=ISOLATION_TIMEOUT)

    if p.is_alive():
        logger.error(
            f"Isolated process exceeded timeout of {ISOLATION_TIMEOUT}s. "
            f"Sending SIGTERM."
        )
        p.terminate()
        p.join(timeout=5)
        if p.is_alive():
            p.kill()  # SIGKILL si SIGTERM no fue suficiente
        raise TimeoutError(
            f"Isolated process killed after {ISOLATION_TIMEOUT}s timeout. "
            f"Possible Tor circuit hang or network stall."
        )
    
    if q.empty():
        raise RuntimeError("Isolated process terminated unexpectedly without returning a result.")
    
    success, value = q.get()
    if success:
        return value
    else:
        raise value


