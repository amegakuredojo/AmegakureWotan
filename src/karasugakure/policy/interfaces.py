import logging
from typing import Dict, Any

logger = logging.getLogger("karasugakure.policy.interfaces")

# Strictly frozen interface definitions and versions
FROZEN_INTERFACES: Dict[str, str] = {
    "schema.prov": "PROV-1.0",
    "schema.audit_trail": "1.2",
    "prompt.odin": "odin_v1.0",
    "prompt.loki": "loki_v1.0",
    "rules.nato_scoring": "NATO-v1.0",
    "format.evidence_bundle": "evidence_v1.1",
    "format.report_dossier": "dossier_v1.2",
}

class InterfaceFreezePolicy:
    """
    Enforces interface freeze. Checks if components use versioned interfaces.
    Any changes that break compatibility require a new declared version.
    """
    @staticmethod
    def get_version(interface_name: str) -> str:
        if interface_name not in FROZEN_INTERFACES:
            raise KeyError(f"Interface '{interface_name}' is not in the frozen interfaces registry.")
        return FROZEN_INTERFACES[interface_name]

    @staticmethod
    def validate_interface_version(interface_name: str, current_version: str) -> bool:
        expected_version = FROZEN_INTERFACES.get(interface_name)
        if not expected_version:
            logger.warning(f"Interface '{interface_name}' is not registered under freeze control.")
            return True
        if expected_version != current_version:
            error_msg = (
                f"INTERFACE COMPATIBILITY BREAK: Interface '{interface_name}' expects version '{expected_version}' "
                f"but got '{current_version}'. Declared migration is required to change frozen interfaces."
            )
            logger.error(error_msg)
            raise ValueError(error_msg)
        return True
