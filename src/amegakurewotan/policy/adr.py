import os
import json
import time
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from amegakurewotan.config import get_config

logger = logging.getLogger("amegakurewotan.policy.adr")

class ADRRegistry:
    """
    Manages operational Architectural & Decision Records (ADRs) and bypass/exception logs.
    Ensures that every exception, scoring change, bypass or exclusion is linked to a valid,
    dated, and reversible ADR.
    """
    def __init__(self):
        config = get_config()
        self.registry_dir = config.base_dir / "opsec"
        self.adr_file = self.registry_dir / "operational_adrs.json"
        self.exception_file = self.registry_dir / "exception_log.json"
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self._init_files()

    def _init_files(self):
        if not self.adr_file.exists():
            with open(self.adr_file, "w") as f:
                json.dump([], f, indent=2)
        if not self.exception_file.exists():
            with open(self.exception_file, "w") as f:
                json.dump([], f, indent=2)

    def create_adr(
        self,
        adr_id: str,
        title: str,
        author: str,
        context: str,
        decision: str,
        consequences: str,
        reversibility_plan: str,
        status: str = "accepted"
    ) -> Dict[str, Any]:
        """Creates a new ADR entry."""
        adr_entry = {
            "adr_id": adr_id,
            "title": title,
            "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": status,
            "author": author,
            "context": context,
            "decision": decision,
            "consequences": consequences,
            "reversibility_plan": reversibility_plan,
            "timestamp": time.time()
        }

        with open(self.adr_file, "r+") as f:
            adrs = json.load(f)
            # Remove duplicate adr_id if it exists
            adrs = [a for a in adrs if a["adr_id"] != adr_id]
            adrs.append(adr_entry)
            f.seek(0)
            f.truncate()
            json.dump(adrs, f, indent=2)

        logger.info(f"ADR '{adr_id}' registered successfully: '{title}' by {author}.")
        return adr_entry

    def get_adr(self, adr_id: str) -> Optional[Dict[str, Any]]:
        with open(self.adr_file, "r") as f:
            adrs = json.load(f)
            for adr in adrs:
                if adr["adr_id"] == adr_id:
                    return adr
        return None

    def log_exception(
        self,
        exception_id: str,
        adr_id: str,
        reason: str,
        operator_id: str,
        affected_component: str
    ) -> Dict[str, Any]:
        """
        Logs an operational exception, bypass, or exclusion.
        Requires linking it to a registered ADR.
        """
        adr = self.get_adr(adr_id)
        if not adr:
            raise ValueError(f"Operational exceptions must reference a registered ADR. ADR '{adr_id}' not found.")

        exception_entry = {
            "exception_id": exception_id,
            "adr_id": adr_id,
            "timestamp": time.time(),
            "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "reason": reason,
            "operator_id": operator_id,
            "affected_component": affected_component,
            "reversibility_plan": adr["reversibility_plan"]
        }

        with open(self.exception_file, "r+") as f:
            exceptions = json.load(f)
            exceptions.append(exception_entry)
            f.seek(0)
            f.truncate()
            json.dump(exceptions, f, indent=2)

        logger.warning(
            f"OPERATIONAL EXCEPTION REGISTERED: '{exception_id}' linked to ADR '{adr_id}' "
            f"for component '{affected_component}' by {operator_id}."
        )
        return exception_entry
