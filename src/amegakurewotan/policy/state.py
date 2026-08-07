import time
import uuid
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger("amegakurewotan.policy.state")

class StateTransitionError(Exception):
    pass

class DualApprovalRegistry:
    """
    Manages dual approval logic for critical findings, policy changes, and operational exceptions.
    Ensures that two separate approvals from distinct operators are required.
    """
    def __init__(self):
        # Maps item_id -> list of approvals: [{"operator_id": str, "signature": str, "reason": str, "timestamp": float}]
        self._approvals: Dict[str, List[Dict[str, Any]]] = {}

    def add_approval(self, item_id: str, operator_id: str, signature: str, reason: str) -> None:
        if not operator_id or not operator_id.strip():
            raise ValueError("Operator ID cannot be empty.")
        if not signature or not signature.strip():
            raise ValueError("Signature cannot be empty.")
        if not reason or not reason.strip():
            raise ValueError("Reason/justification must be documented.")

        if item_id not in self._approvals:
            self._approvals[item_id] = []

        # Check if this operator already approved
        for app in self._approvals[item_id]:
            if app["operator_id"] == operator_id:
                raise ValueError(f"Operator '{operator_id}' has already approved item '{item_id}'. Two unique approvals are required.")

        self._approvals[item_id].append({
            "operator_id": operator_id,
            "signature": signature,
            "reason": reason,
            "timestamp": time.time()
        })
        logger.info(f"Approval registered for item '{item_id}' by operator '{operator_id}'.")

    def get_approvals(self, item_id: str) -> List[Dict[str, Any]]:
        return self._approvals.get(item_id, [])

    def is_approved(self, item_id: str, required_approvals: int = 2) -> bool:
        approvals = self.get_approvals(item_id)
        # Ensure we have at least required_approvals distinct approvals
        distinct_operators = {app["operator_id"] for app in approvals}
        return len(distinct_operators) >= required_approvals

    def clear_approvals(self, item_id: str) -> None:
        if item_id in self._approvals:
            del self._approvals[item_id]


class FindingStateMachine:
    """
    Implements a strict state machine for OSINT findings and investigation states.
    Valid states: draft, triaged, reproduced, validated_5_5, reviewed, promoted, rejected, retired.
    Enforces transitions and prevents direct promotion from draft to promoted.
    """
    VALID_STATES = {
        "draft", "triaged", "reproduced", "validated_5_5",
        "reviewed", "promoted", "rejected", "retired"
    }

    # Allowed transitions map: state -> allowed next states
    ALLOWED_TRANSITIONS = {
        "draft": {"triaged", "rejected"},
        "triaged": {"reproduced", "rejected"},
        "reproduced": {"validated_5_5", "rejected"},
        "validated_5_5": {"reviewed", "rejected"},
        "reviewed": {"promoted", "rejected", "retired"},
        "promoted": {"retired"},
        "rejected": {"retired", "draft"},
        "retired": {"draft"}  # Allow reactivation if needed
    }

    def __init__(self, dual_approval_registry: Optional[DualApprovalRegistry] = None):
        # Maps finding_id -> current state
        self._states: Dict[str, str] = {}
        # Maps finding_id -> list of transition records: [{"from": str, "to": str, "author": str, "reason": str, "timestamp": float}]
        self._history: Dict[str, List[Dict[str, Any]]] = {}
        self.registry = dual_approval_registry or DualApprovalRegistry()

    def get_state(self, finding_id: str) -> str:
        return self._states.get(finding_id, "draft")

    def get_history(self, finding_id: str) -> List[Dict[str, Any]]:
        return self._history.get(finding_id, [])

    def transition_to(
        self,
        finding_id: str,
        to_state: str,
        author_id: str,
        reason: str,
        is_critical: bool = False
    ) -> str:
        if to_state not in self.VALID_STATES:
            raise ValueError(f"Invalid state: '{to_state}'. Valid states are: {self.VALID_STATES}")

        current_state = self.get_state(finding_id)
        if current_state == to_state:
            return current_state

        allowed_next = self.ALLOWED_TRANSITIONS.get(current_state, set())
        if to_state not in allowed_next:
            raise StateTransitionError(
                f"Invalid state transition: Cannot move finding '{finding_id}' from '{current_state}' directly to '{to_state}'. "
                f"Allowed transitions from '{current_state}' are: {allowed_next}"
            )

        # Enforce Dual Approval for promotion to promoted if critical
        if to_state == "promoted" and is_critical:
            if not self.registry.is_approved(finding_id, required_approvals=2):
                approvals = self.registry.get_approvals(finding_id)
                raise StateTransitionError(
                    f"Dual approval required to promote critical finding '{finding_id}'. "
                    f"Current approvals: {len(approvals)}/2. Two distinct signatures must be registered first."
                )

        # Record transition
        if finding_id not in self._history:
            self._history[finding_id] = []

        transition_record = {
            "from_state": current_state,
            "to_state": to_state,
            "author_id": author_id,
            "reason": reason,
            "timestamp": time.time()
        }
        self._history[finding_id].append(transition_record)
        self._states[finding_id] = to_state

        logger.info(f"Finding '{finding_id}' transitioned from '{current_state}' to '{to_state}' by '{author_id}'.")
        return to_state
