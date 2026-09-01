from dataclasses import dataclass


@dataclass
class AuthzRequest:
    agent_id: str
    action: str
    resource: str


@dataclass
class AuthzDecision:
    allowed: bool
    reason: str


class PolicyDecisionPoint:
    """Minimal PDP. Hardcoded policy — plain code, not OPA/Cedar."""

    def __init__(self):
        self._policies = {
            "validator": {"allowed_actions": ["control_check"]},
            "reporter": {"allowed_actions": ["generate_report"]},
            "human": {"allowed_actions": ["approve_containment"]},
        }

    def authorize(self, request: AuthzRequest) -> AuthzDecision:
        policy = self._policies.get(request.agent_id)
        if policy is None:
            return AuthzDecision(
                allowed=False,
                reason=f"No policy for agent '{request.agent_id}'",
            )
        if request.action not in policy["allowed_actions"]:
            return AuthzDecision(
                allowed=False,
                reason=f"Agent '{request.agent_id}' not authorized for '{request.action}'",
            )
        return AuthzDecision(allowed=True, reason="Policy allows action")
