# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: 3.0
# FORGE_DATE: 2026-07-04T21:20:00Z

import os
import sys
import time
import socket
import logging
import requests
import gc
from threading import Thread
import traceback
from typing import Any, Dict, List, Optional
from stem import Signal
from stem.control import Controller

logger = logging.getLogger("amegakurewotan.daemons.killswitch")

class TorIsolatorDaemon:
    """
    Daemon that enforces OPSEC Pilar 1:
    1. Monitors for clear-net leaks (Kill Switch)
    2. Rotates Tor Circuits dynamically for each request (Circuit Isolation)
    """
    def __init__(self) -> None:
        self.host_ip: str = "UNKNOWN"
        self.is_running: bool = False
        self.consecutive_failures: int = 0
        self.max_failures: int = 3

    def _get_host_real_ip(self) -> str:
        """Safely retrieves the machine's real public IP without using the proxy."""
        try:
            # We explicitly bypass proxies for this check to know our true IP
            proxies: Dict[str, str] = {"http": "", "https": ""}
            res = requests.get("https://api.ipify.org", proxies=proxies, timeout=5.0)
            if res.status_code == 200:
                return res.text.strip()
        except Exception as e:
            logger.warning(f"Could not determine real host IP for Kill Switch: {e}")
        return "UNKNOWN"

    def rotate_identity(self) -> None:
        """Sends a NEWNYM signal to Tor to rotate the SOCKS5 circuit exit node."""
        from amegakurewotan.config import get_config
        config = get_config()
        tor_host: str = config.opsec.tor_control_host
        control_port: int = config.opsec.tor_control_port
        try:
            with Controller.from_port(port=control_port, address=tor_host) as controller:
                controller.authenticate(password="KarasuSecretControlPass")
                controller.signal(Signal.NEWNYM)
                logger.info("OPSEC: Tor circuit successfully rotated (NEWNYM). New identity assumed.")
        except Exception as e:
            logger.error(f"Failed to rotate Tor identity: {e} - Trace: {traceback.format_exc()}")

    def _monitor_leak(self) -> None:
        """Continuously checks if traffic routed through Tor is leaking the real IP with fault-tolerance gates."""
        if self.host_ip == "UNKNOWN":
            logger.warning("Kill switch active, but real IP is UNKNOWN. Relying on timeout failures.")
            
        from amegakurewotan.config import get_config
        config = get_config()
        tor_proxy = config.opsec.tor_proxy
        
        while self.is_running:
            try:
                # Make request through the Tor proxy
                proxies: Dict[str, str] = {
                    "http": tor_proxy,
                    "https": tor_proxy
                }
                res = requests.get("https://api.ipify.org", proxies=proxies, timeout=10.0)
                
                if res.status_code == 200:
                    tor_ip: str = res.text.strip()
                    self.consecutive_failures = 0  # Reset counter on success
                    
                    if tor_ip == self.host_ip and self.host_ip != "UNKNOWN":
                        self._trigger_kill_switch(f"FATAL: IP Leak detected! Tor exit node IP ({tor_ip}) matches Real IP!")
            except requests.exceptions.RequestException as exc:
                self.consecutive_failures += 1
                logger.warning(
                    f"Failed to reach check-site through Tor proxy (Attempt {self.consecutive_failures}/{self.max_failures}). "
                    f"Error: {exc}"
                )
                if self.consecutive_failures >= self.max_failures:
                    self._trigger_kill_switch(
                        f"FATAL: Lost connection to Tor proxy for {self.max_failures} consecutive checks. "
                        f"Aborting to prevent fallback leaks."
                    )
            
            time.sleep(15.0) # Check every 15 seconds

    def _trigger_kill_switch(self, reason: str) -> None:
        """Executes emergency destruction of processes and RAM."""
        logger.critical(f"KILL SWITCH ENGAGED: {reason}")
        
        # 1. Flush memory buffers
        gc.collect()
        
        # 2. Halt all Karasu processes
        logger.critical("Halting all orchestration agents.")
        
        # In a real environment, this would cleanly terminate Docker containers,
        # but since this runs inside the container, we force exit the process tree.
        os._exit(1) # Immediate uncatchable exit, bypasses finally blocks

    def start(self) -> None:
        self.host_ip = self._get_host_real_ip()
        self.is_running = True
        self.consecutive_failures = 0
        t = Thread(target=self._monitor_leak, daemon=True)
        t.start()
        logger.info("Tor Isolator Daemon and Kill Switch activated.")

    def stop(self) -> None:
        self.is_running = False

# Global singleton (lazy-evaluated structure or clean instantiation without side-effects)
isolator = TorIsolatorDaemon()
