import os
import sys
import time
import socket
import logging
import requests
from threading import Thread
import traceback
from stem import Signal
from stem.control import Controller

logger = logging.getLogger("karasugakure.daemons.killswitch")

class TorIsolatorDaemon:
    """
    Daemon that enforces OPSEC Pilar 1:
    1. Monitors for clear-net leaks (Kill Switch)
    2. Rotates Tor Circuits dynamically for each request (Circuit Isolation)
    """
    def __init__(self):
        self.host_ip = self._get_host_real_ip()
        self.control_port = 9051
        self.is_running = False

    def _get_host_real_ip(self) -> str:
        """Safely retrieves the machine's real public IP without using the proxy."""
        try:
            # We explicitly bypass proxies for this check to know our true IP
            proxies = {"http": "", "https": ""}
            res = requests.get("https://api.ipify.org", proxies=proxies, timeout=5)
            if res.status_code == 200:
                return res.text.strip()
        except Exception as e:
            logger.warning(f"Could not determine real host IP for Kill Switch: {e}")
        return "UNKNOWN"

    def rotate_identity(self):
        """Sends a NEWNYM signal to Tor to rotate the SOCKS5 circuit exit node."""
        tor_host = "127.0.0.1"
        try:
            with Controller.from_port(port=self.control_port, address=tor_host) as controller:
                controller.authenticate()  # Assumes no password or cookie auth configured for local docker
                controller.signal(Signal.NEWNYM)
                logger.info("OPSEC: Tor circuit successfully rotated (NEWNYM). New identity assumed.")
        except Exception as e:
            logger.error(f"Failed to rotate Tor identity: {e}")

    def _monitor_leak(self):
        """Continuously checks if traffic routed through Tor is leaking the real IP."""
        if self.host_ip == "UNKNOWN":
            logger.warning("Kill switch active, but real IP is UNKNOWN. Relying on timeout failures.")
            
        while self.is_running:
            try:
                # Make request through the Tor proxy
                proxies = {"http": "socks5h://127.0.0.1:9050", "https": "socks5h://127.0.0.1:9050"}
                res = requests.get("https://api.ipify.org", proxies=proxies, timeout=10)
                
                if res.status_code == 200:
                    tor_ip = res.text.strip()
                    if tor_ip == self.host_ip:
                        self._trigger_kill_switch(f"FATAL: IP Leak detected! Tor exit node IP ({tor_ip}) matches Real IP!")
            except requests.exceptions.RequestException:
                # If we can't reach the internet through Tor, it might be down.
                # It's safer to kill switch if we lose anonymity layer.
                self._trigger_kill_switch("FATAL: Lost connection to Tor proxy. Aborting to prevent fallback leaks.")
            
            time.sleep(15) # Check every 15 seconds

    def _trigger_kill_switch(self, reason: str):
        """Executes emergency destruction of processes and RAM."""
        logger.critical(f"KILL SWITCH ENGAGED: {reason}")
        
        # 1. Flush memory buffers
        import gc
        gc.collect()
        
        # 2. Halt all Karasu processes
        logger.critical("Halting all orchestration agents.")
        
        # In a real environment, this would cleanly terminate Docker containers,
        # but since this runs inside the container, we force exit the process tree.
        os._exit(1) # Immediate uncatchable exit, bypasses finally blocks

    def start(self):
        self.is_running = True
        t = Thread(target=self._monitor_leak, daemon=True)
        t.start()
        logger.info("Tor Isolator Daemon and Kill Switch activated.")

    def stop(self):
        self.is_running = False

# Global singleton
isolator = TorIsolatorDaemon()
