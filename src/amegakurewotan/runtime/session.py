import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from amegakurewotan.utils.fs import get_session_dir

logger = logging.getLogger("amegakurewotan.runtime.session")

class Session:
    def __init__(self, session_id: str = "default"):
        self.session_id = session_id
        self.filepath = get_session_dir() / f"{session_id}.json"
        self.data: Dict[str, Any] = {
            "session_id": session_id,
            "targets": [],
            "history": [],
            "metadata": {}
        }
        
    def load(self) -> bool:
        """Loads session data from file."""
        if self.filepath.exists():
            try:
                with open(self.filepath, "r") as f:
                    self.data = json.load(f)
                logger.info(f"Loaded session '{self.session_id}' from {self.filepath}")
                return True
            except Exception as e:
                logger.error(f"Failed to load session '{self.session_id}': {e}")
        return False

    def save(self) -> bool:
        """Saves current session data to file."""
        try:
            with open(self.filepath, "w") as f:
                json.dump(self.data, f, indent=2)
            logger.debug(f"Saved session '{self.session_id}' to {self.filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to save session '{self.session_id}': {e}")
            return False

    def add_target(self, target: str, target_type: str):
        """Adds a target to session if it doesn't exist."""
        target_entry = {"value": target, "type": target_type}
        if target_entry not in self.data["targets"]:
            self.data["targets"].append(target_entry)
            self.save()

    def log_action(self, agent_name: str, action: str, result_summary: str):
        """Logs an action taken in this session."""
        self.data["history"].append({
            "agent": agent_name,
            "action": action,
            "summary": result_summary
        })
        self.save()
