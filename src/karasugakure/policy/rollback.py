import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from karasugakure.config import get_config

logger = logging.getLogger("karasugakure.policy.rollback")

# Pre-defined versions mapping for rules, prompts, and templates
VERSIONED_REGISTRY: Dict[str, Dict[str, Any]] = {
    "v1.0": {
        "rules.nato_scoring": {
            "reliability_map": {"A": 1.0, "B": 0.8, "C": 0.6, "D": 0.4, "E": 0.2, "F": 0.0},
            "credibility_map": {"1": 1.0, "2": 0.8, "3": 0.6, "4": 0.4, "5": 0.2, "6": 0.0}
        },
        "prompts.odin": "Execute standard OSINT scan workflow.",
        "templates.report": "# OSINT INVESTIGATION DOSSIER: {target}\nStatus: {status}\n"
    },
    "v1.1": {
        "rules.nato_scoring": {
            "reliability_map": {"A": 1.0, "B": 0.9, "C": 0.7, "D": 0.5, "E": 0.3, "F": 0.0},
            "credibility_map": {"1": 1.0, "2": 0.9, "3": 0.7, "4": 0.5, "5": 0.3, "6": 0.0}
        },
        "prompts.odin": "Execute rigorous, state-governed OSINT scan workflow under 9.4+ guidelines.",
        "templates.report": "# OSINT INVESTIGATION DOSSIER: {target}\nStatus: {status}\nMetadata:\n- Run ID: {run_id}\n- Operator ID: {operator_id}\n"
    }
}

class ReleaseTrainManager:
    """
    Manages release trains and rollbacks of rules, prompts, templates and pipeline behaviors.
    Saves active version configuration in a local environment settings file.
    """
    def __init__(self):
        config = get_config()
        self.config_path = config.base_dir / "opsec" / "active_release_version.json"
        if not self.config_path.exists():
            self.set_active_version("v1.1")

    def get_active_version(self) -> str:
        try:
            if self.config_path.exists():
                with open(self.config_path, "r") as f:
                    data = json.load(f)
                    return data.get("version", "v1.1")
        except Exception:
            pass
        return "v1.1"

    def set_active_version(self, version: str) -> None:
        if version not in VERSIONED_REGISTRY:
            raise ValueError(f"Version '{version}' is not registered in the release train. Available: {list(VERSIONED_REGISTRY.keys())}")
        
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w") as f:
            json.dump({"version": version}, f, indent=2)
        logger.warning(f"RELEASE TRAIN ACTION: Active operational version switched/rolled back to: {version}")

    def get_active_resource(self, resource_key: str) -> Any:
        version = self.get_active_version()
        version_data = VERSIONED_REGISTRY.get(version, VERSIONED_REGISTRY["v1.1"])
        if resource_key not in version_data:
            # Fallback to current version registry if missing
            return VERSIONED_REGISTRY["v1.1"].get(resource_key)
        return version_data[resource_key]

    def test_rollback_cycle(self) -> bool:
        """Executes a simulated rollback and recovery test cycle."""
        logger.info("Executing Release Train rollback self-test...")
        original = self.get_active_version()
        try:
            # Step 1: Rollback to v1.0
            self.set_active_version("v1.0")
            assert self.get_active_version() == "v1.0"
            r_scoring = self.get_active_resource("rules.nato_scoring")
            assert r_scoring["reliability_map"]["B"] == 0.8
            
            # Step 2: Rollforward to v1.1
            self.set_active_version("v1.1")
            assert self.get_active_version() == "v1.1"
            r_scoring_new = self.get_active_resource("rules.nato_scoring")
            assert r_scoring_new["reliability_map"]["B"] == 0.9

            logger.info("Release Train rollback self-test completed successfully.")
            return True
        except Exception as e:
            logger.error(f"Release Train rollback self-test FAILED: {e}")
            # Restore original
            try:
                self.set_active_version(original)
            except Exception:
                pass
            return False
