# compliance_lab/workflow.py
"""Slice 3 LangGraph workflow — two-agent control validation with human-in-the-loop containment gate."""

import json
from pathlib import Path
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from compliance_lab.agent import (
    CONTROL_IA5_1,
    build_check_prompt,
    build_report_prompt,
    parse_containment,
    parse_finding,
    parse_report,
)
from compliance_lab.agents import ComplianceAgent
from compliance_lab.audit import AuditLogger
from compliance_lab.authz import AuthzRequest, PolicyDecisionPoint
from compliance_lab.identity import AgentIdentity
from compliance_lab.targets import get_target_by_id


class WorkflowState(TypedDict, total=False):
    control_id: str
    target_id: str
    target_data: dict
    check_authz_allowed: bool
    check_authz_reason: str
    finding: str
    evidence: str
    report_authz_allowed: bool
    report_authz_reason: str
    report_summary: str
    report_recommendation: str
    containment_action: str
    containment_justification: str
    containment_approved: bool
    containment_approval_reason: str
    containment_executed: bool


def build_workflow(
    validator: ComplianceAgent,
    reporter: ComplianceAgent,
    pdp: PolicyDecisionPoint,
    audit_logger: AuditLogger,
    targets_dir: Path,
    control_store=None,
    human_identity: AgentIdentity = None,
    approval_callback=None,
):
    """Build and compile the Slice 3 LangGraph workflow.

    Args:
        control_store: Optional ControlStore for RAG-grounded control retrieval.
            When provided, check_phase calls control_store.retrieve(control_id)
            instead of using the hardcoded CONTROL_IA5_1 constant.
        human_identity: Optional AgentIdentity for the human approver.
            Required (with approval_callback) to enable the containment gate.
        approval_callback: Optional async callable (proposal: dict) -> bool.
            Called when a containment action needs human approval.

    Graph shape:
        START → load_target → check_phase ──[check allowed]──→ report_phase
                                            └──[check denied]──→ END

        report_phase ──[containment proposed + callback configured]──→ containment_phase
                     └──[no containment]──→ END

        containment_phase ──[approved]──→ execute_containment → END
                          └──[denied]──→ END

    Each phase: authorize → execute → audit (or authorize → audit denial).
    """

    async def load_target(state: WorkflowState) -> dict:
        target_data = get_target_by_id(targets_dir, state["target_id"])
        return {"target_data": target_data}

    async def check_phase(state: WorkflowState) -> dict:
        # Authorize
        request = AuthzRequest(
            agent_id=validator.identity.agent_id,
            action="control_check",
            resource=state["target_id"],
        )
        decision = pdp.authorize(request)

        if not decision.allowed:
            # Log denial and return
            action = "authorization_denied"
            detail = json.dumps({
                "control_id": state["control_id"],
                "phase": "check",
                "reason": decision.reason,
            })
            message = f"{action}:{state['target_id']}:{detail}"
            signature = validator.identity.sign(message.encode())
            audit_logger.log(
                agent_id=validator.identity.agent_id,
                action=action,
                resource=state["target_id"],
                detail=detail,
                signature=signature,
            )
            return {
                "check_authz_allowed": False,
                "check_authz_reason": decision.reason,
            }

        # Execute check
        if control_store is not None:
            control_text = control_store.retrieve(state["control_id"])
        else:
            control_text = CONTROL_IA5_1
        prompt = build_check_prompt(state["target_data"], control_text)
        response = await validator.run(prompt)
        result = parse_finding(response)

        # Audit
        action = "control_check"
        detail = json.dumps({
            "control_id": state["control_id"],
            "finding": result["finding"],
            "evidence": result["evidence"],
        })
        message = f"{action}:{state['target_id']}:{detail}"
        signature = validator.identity.sign(message.encode())
        audit_logger.log(
            agent_id=validator.identity.agent_id,
            action=action,
            resource=state["target_id"],
            detail=detail,
            signature=signature,
        )

        return {
            "check_authz_allowed": True,
            "check_authz_reason": decision.reason,
            "finding": result["finding"],
            "evidence": result["evidence"],
        }

    async def report_phase(state: WorkflowState) -> dict:
        # Authorize
        request = AuthzRequest(
            agent_id=reporter.identity.agent_id,
            action="generate_report",
            resource=state["target_id"],
        )
        decision = pdp.authorize(request)

        if not decision.allowed:
            action = "authorization_denied"
            detail = json.dumps({
                "control_id": state["control_id"],
                "phase": "report",
                "reason": decision.reason,
            })
            message = f"{action}:{state['target_id']}:{detail}"
            signature = reporter.identity.sign(message.encode())
            audit_logger.log(
                agent_id=reporter.identity.agent_id,
                action=action,
                resource=state["target_id"],
                detail=detail,
                signature=signature,
            )
            return {
                "report_authz_allowed": False,
                "report_authz_reason": decision.reason,
            }

        # Execute report
        prompt = build_report_prompt(
            state["finding"], state["evidence"],
            state["target_data"], state["control_id"],
        )
        response = await reporter.run(prompt)
        result = parse_report(response)
        containment = parse_containment(response)

        # Audit
        action = "generate_report"
        detail = json.dumps({
            "control_id": state["control_id"],
            "summary": result["summary"],
            "recommendation": result["recommendation"],
        })
        message = f"{action}:{state['target_id']}:{detail}"
        signature = reporter.identity.sign(message.encode())
        audit_logger.log(
            agent_id=reporter.identity.agent_id,
            action=action,
            resource=state["target_id"],
            detail=detail,
            signature=signature,
        )

        return {
            "report_authz_allowed": True,
            "report_authz_reason": decision.reason,
            "report_summary": result["summary"],
            "report_recommendation": result["recommendation"],
            "containment_action": containment["containment_action"],
            "containment_justification": containment["containment_justification"],
        }

    async def containment_phase(state: WorkflowState) -> dict:
        """Request human approval for containment action."""
        # Authorize the human
        request = AuthzRequest(
            agent_id=human_identity.agent_id,
            action="approve_containment",
            resource=state["target_id"],
        )
        decision = pdp.authorize(request)

        if not decision.allowed:
            action = "authorization_denied"
            detail = json.dumps({
                "control_id": state["control_id"],
                "phase": "containment_approval",
                "reason": decision.reason,
            })
            message = f"{action}:{state['target_id']}:{detail}"
            signature = human_identity.sign(message.encode())
            audit_logger.log(
                agent_id=human_identity.agent_id,
                action=action,
                resource=state["target_id"],
                detail=detail,
                signature=signature,
            )
            return {
                "containment_approved": False,
                "containment_approval_reason": decision.reason,
            }

        # Request human approval via callback
        proposal = {
            "control_id": state["control_id"],
            "target_id": state["target_id"],
            "finding": state["finding"],
            "containment_action": state["containment_action"],
            "containment_justification": state["containment_justification"],
        }
        approved = await approval_callback(proposal)

        # Audit the approval decision
        action = "approve_containment" if approved else "deny_containment"
        detail = json.dumps({
            "control_id": state["control_id"],
            "containment_action": state["containment_action"],
            "approved": approved,
        })
        message = f"{action}:{state['target_id']}:{detail}"
        signature = human_identity.sign(message.encode())
        audit_logger.log(
            agent_id=human_identity.agent_id,
            action=action,
            resource=state["target_id"],
            detail=detail,
            signature=signature,
        )

        return {
            "containment_approved": approved,
            "containment_approval_reason": "Human approved" if approved else "Human denied",
        }

    async def execute_containment(state: WorkflowState) -> dict:
        """Execute the approved containment action (simulated)."""
        action = "execute_containment"
        detail = json.dumps({
            "control_id": state["control_id"],
            "containment_action": state["containment_action"],
            "simulated": True,
        })
        message = f"{action}:{state['target_id']}:{detail}"
        signature = validator.identity.sign(message.encode())
        audit_logger.log(
            agent_id=validator.identity.agent_id,
            action=action,
            resource=state["target_id"],
            detail=detail,
            signature=signature,
        )
        return {"containment_executed": True}

    def route_after_check(state: WorkflowState) -> str:
        if state.get("check_authz_allowed"):
            return "report_phase"
        return END

    def route_after_report(state: WorkflowState) -> str:
        if state.get("containment_action") and human_identity and approval_callback:
            return "containment_phase"
        return END

    def route_after_containment(state: WorkflowState) -> str:
        if state.get("containment_approved"):
            return "execute_containment"
        return END

    graph = StateGraph(WorkflowState)
    graph.add_node("load_target", load_target)
    graph.add_node("check_phase", check_phase)
    graph.add_node("report_phase", report_phase)
    graph.add_node("containment_phase", containment_phase)
    graph.add_node("execute_containment", execute_containment)

    graph.add_edge(START, "load_target")
    graph.add_edge("load_target", "check_phase")
    graph.add_conditional_edges("check_phase", route_after_check)
    graph.add_conditional_edges("report_phase", route_after_report)
    graph.add_conditional_edges("containment_phase", route_after_containment)
    graph.add_edge("execute_containment", END)

    return graph.compile()
