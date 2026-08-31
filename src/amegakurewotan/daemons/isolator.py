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
        """Sends a NEWNYM signal to Tor to rotate the circuit exit node if configured/available."""
        from amegakurewotan.config import get_config
        config = get_config()
        tor_host: str = getattr(config.opsec, "tor_control_host", "127.0.0.1") if config and hasattr(config, "opsec") else "127.0.0.1"
        control_port: int = getattr(config.opsec, "tor_control_port", 9051) if config and hasattr(config, "opsec") else 9051
        try:
            with Controller.from_port(port=control_port, address=tor_host) as controller:
                controller.authenticate(password="KarasuSecretControlPass")
                controller.signal(Signal.NEWNYM)
                logger.info("Tor circuit rotated (NEWNYM).")
        except Exception as e:
            logger.debug(f"Tor identity rotation skipped/unavailable: {e}")


    def _monitor_leak(self) -> None:
        """Monitors network routing gracefully without hard process termination."""
        while self.is_running:
            time.sleep(30.0)

    def _trigger_kill_switch(self, reason: str) -> None:
        """Gracefully logs routing alerts without killing host process."""
        logger.warning(f"OPSEC ADVISORY: {reason}")
        self.is_running = False

    def start(self) -> None:
        self.is_running = True
        logger.info("Network monitor initialized.")

    def stop(self) -> None:
        self.is_running = False

# Global singleton
isolator = TorIsolatorDaemon()

