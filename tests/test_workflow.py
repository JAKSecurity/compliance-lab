# tests/test_workflow.py
from unittest.mock import AsyncMock, MagicMock

from compliance_lab.agent import CONTROL_IA5_1
from compliance_lab.agents import ComplianceAgent
from compliance_lab.audit import AuditLogger
from compliance_lab.authz import PolicyDecisionPoint
from compliance_lab.identity import AgentIdentity
from compliance_lab.workflow import build_workflow


class FakeControlStore:
    """Returns hardcoded control text. Stands in for ControlStore in tests."""
    def retrieve(self, query):
        return CONTROL_IA5_1
    def is_indexed(self):
        return True


class SpyControlStore:
    """Records retrieve() calls for assertion."""
    def __init__(self, return_text=CONTROL_IA5_1):
        self._return_text = return_text
        self.queries = []
    def retrieve(self, query):
        self.queries.append(query)
        return self._return_text
    def is_indexed(self):
        return True


def _make_mock_agent(role: str, agent_id: str, response: str) -> ComplianceAgent:
    """Create a ComplianceAgent with a mocked run() method."""
    identity = AgentIdentity.generate(agent_id)
    mock_autogen = AsyncMock()
    mock_result = MagicMock()
    mock_message = MagicMock()
    mock_message.content = response
    mock_result.messages = [mock_message]
    mock_autogen.run.return_value = mock_result

    return ComplianceAgent(role=role, identity=identity, autogen_agent=mock_autogen)


async def test_workflow_full_pass(tmp_path, targets_dir):
    validator = _make_mock_agent(
        "validator", "validator",
        '{"finding": "PASS", "evidence": "Password policy meets all requirements"}',
    )
    reporter = _make_mock_agent(
        "reporter", "reporter",
        '{"summary": "System is compliant", "recommendation": "No action needed"}',
    )
    pdp = PolicyDecisionPoint()
    audit = AuditLogger(tmp_path / "audit.jsonl")

    app = build_workflow(validator, reporter, pdp, audit, targets_dir, FakeControlStore())
    result = await app.ainvoke({"control_id": "IA-5(1)", "target_id": "synth-web-001"})

    assert result["finding"] == "PASS"
    assert result["report_summary"] == "System is compliant"
    assert result["check_authz_allowed"] is True
    assert result["report_authz_allowed"] is True
    assert audit.entry_count() == 2
    assert audit.verify_chain()


async def test_workflow_full_fail(tmp_path, targets_dir):
    validator = _make_mock_agent(
        "validator", "validator",
        '{"finding": "FAIL", "evidence": "Password length below minimum"}',
    )
    reporter = _make_mock_agent(
        "reporter", "reporter",
        '{"summary": "Non-compliant", "recommendation": "Increase password length"}',
    )
    pdp = PolicyDecisionPoint()
    audit = AuditLogger(tmp_path / "audit.jsonl")

    app = build_workflow(validator, reporter, pdp, audit, targets_dir, FakeControlStore())
    result = await app.ainvoke({"control_id": "IA-5(1)", "target_id": "synth-web-001"})

    assert result["finding"] == "FAIL"
    assert result["report_summary"] == "Non-compliant"
    assert audit.entry_count() == 2
    assert audit.verify_chain()


async def test_workflow_check_authz_denied(tmp_path, targets_dir):
    intruder = _make_mock_agent("validator", "intruder", "should not be called")
    reporter = _make_mock_agent(
        "reporter", "reporter",
        '{"summary": "OK", "recommendation": "None"}',
    )
    pdp = PolicyDecisionPoint()
    audit = AuditLogger(tmp_path / "audit.jsonl")

    app = build_workflow(intruder, reporter, pdp, audit, targets_dir, FakeControlStore())
    result = await app.ainvoke({"control_id": "IA-5(1)", "target_id": "synth-web-001"})

    assert result["check_authz_allowed"] is False
    assert result.get("finding") is None
    assert result.get("report_summary") is None
    assert audit.entry_count() == 1
    assert audit.verify_chain()
    entry = audit.entries[0]
    assert entry["action"] == "authorization_denied"


async def test_workflow_report_authz_denied(tmp_path, targets_dir):
    validator = _make_mock_agent(
        "validator", "validator",
        '{"finding": "PASS", "evidence": "OK"}',
    )
    # Reporter with wrong agent_id — not in policy
    bad_reporter = _make_mock_agent("reporter", "intruder", "should not be called")
    pdp = PolicyDecisionPoint()
    audit = AuditLogger(tmp_path / "audit.jsonl")

    app = build_workflow(validator, bad_reporter, pdp, audit, targets_dir, FakeControlStore())
    result = await app.ainvoke({"control_id": "IA-5(1)", "target_id": "synth-web-001"})

    assert result["check_authz_allowed"] is True
    assert result["finding"] == "PASS"
    assert result["report_authz_allowed"] is False
    assert result.get("report_summary") is None
    assert audit.entry_count() == 2
    assert audit.verify_chain()


async def test_workflow_audit_entries_have_valid_signatures(tmp_path, targets_dir):
    validator = _make_mock_agent(
        "validator", "validator",
        '{"finding": "PASS", "evidence": "OK"}',
    )
    reporter = _make_mock_agent(
        "reporter", "reporter",
        '{"summary": "Compliant", "recommendation": "None"}',
    )
    pdp = PolicyDecisionPoint()
    audit = AuditLogger(tmp_path / "audit.jsonl")

    app = build_workflow(validator, reporter, pdp, audit, targets_dir, FakeControlStore())
    await app.ainvoke({"control_id": "IA-5(1)", "target_id": "synth-web-001"})

    # Entry 0: validator's check — signed by validator
    entry0 = audit.entries[0]
    msg0 = f"{entry0['action']}:{entry0['resource']}:{entry0['detail']}"
    assert validator.identity.verify(bytes.fromhex(entry0["signature"]), msg0.encode())

    # Entry 1: reporter's report — signed by reporter
    entry1 = audit.entries[1]
    msg1 = f"{entry1['action']}:{entry1['resource']}:{entry1['detail']}"
    assert reporter.identity.verify(bytes.fromhex(entry1["signature"]), msg1.encode())


async def test_workflow_cross_role_denied(tmp_path, targets_dir):
    """Validator agent passed as reporter — authz blocks because agent_id 'validator'
    is not authorized for 'generate_report'."""
    validator = _make_mock_agent(
        "validator", "validator",
        '{"finding": "PASS", "evidence": "OK"}',
    )
    wrong_role = _make_mock_agent("reporter", "validator", "should not be called")
    pdp = PolicyDecisionPoint()
    audit = AuditLogger(tmp_path / "audit.jsonl")

    app = build_workflow(validator, wrong_role, pdp, audit, targets_dir, FakeControlStore())
    result = await app.ainvoke({"control_id": "IA-5(1)", "target_id": "synth-web-001"})

    assert result["check_authz_allowed"] is True
    assert result["report_authz_allowed"] is False
    assert audit.entry_count() == 2


async def test_workflow_uses_control_store_for_retrieval(tmp_path, targets_dir):
    """Verify the workflow calls control_store.retrieve() with the control_id."""
    validator = _make_mock_agent(
        "validator", "validator",
        '{"finding": "PASS", "evidence": "OK"}',
    )
    reporter = _make_mock_agent(
        "reporter", "reporter",
        '{"summary": "Compliant", "recommendation": "None"}',
    )
    pdp = PolicyDecisionPoint()
    audit = AuditLogger(tmp_path / "audit.jsonl")
    spy = SpyControlStore()

    app = build_workflow(validator, reporter, pdp, audit, targets_dir, spy)
    await app.ainvoke({"control_id": "IA-5(1)", "target_id": "synth-web-001"})

    assert len(spy.queries) == 1
    assert "IA-5(1)" in spy.queries[0]


# --- Containment gate tests (Slice 3) ---


async def _auto_approve(proposal):
    return True


async def _auto_deny(proposal):
    return False


async def test_workflow_pass_skips_containment(tmp_path, targets_dir):
    """PASS finding — no containment proposed, workflow ends after report."""
    validator = _make_mock_agent(
        "validator", "validator",
        '{"finding": "PASS", "evidence": "All good"}',
    )
    reporter = _make_mock_agent(
        "reporter", "reporter",
        '{"summary": "Compliant", "recommendation": "None"}',
    )
    human = AgentIdentity.generate("human")
    pdp = PolicyDecisionPoint()
    audit = AuditLogger(tmp_path / "audit.jsonl")

    app = build_workflow(
        validator, reporter, pdp, audit, targets_dir,
        FakeControlStore(), human, _auto_approve,
    )
    result = await app.ainvoke({"control_id": "IA-5(1)", "target_id": "synth-web-001"})

    assert result["finding"] == "PASS"
    assert result.get("containment_action") is None
    assert result.get("containment_approved") is None
    assert audit.entry_count() == 2  # check + report, no containment


async def test_workflow_fail_triggers_containment_approved(tmp_path, targets_dir):
    """FAIL finding -> containment proposed -> human approves -> executed."""
    validator = _make_mock_agent(
        "validator", "validator",
        '{"finding": "FAIL", "evidence": "Password too short"}',
    )
    reporter = _make_mock_agent(
        "reporter", "reporter",
        '{"summary": "Non-compliant", "recommendation": "Fix password policy", "containment_action": "Isolate system", "containment_justification": "Failed check"}',
    )
    human = AgentIdentity.generate("human")
    pdp = PolicyDecisionPoint()
    audit = AuditLogger(tmp_path / "audit.jsonl")

    app = build_workflow(
        validator, reporter, pdp, audit, targets_dir,
        FakeControlStore(), human, _auto_approve,
    )
    result = await app.ainvoke({"control_id": "IA-5(1)", "target_id": "synth-web-001"})

    assert result["finding"] == "FAIL"
    assert result["containment_action"] == "Isolate system"
    assert result["containment_approved"] is True
    assert result["containment_executed"] is True
    assert audit.entry_count() == 4  # check + report + approval + execution
    assert audit.verify_chain()


async def test_workflow_fail_containment_denied(tmp_path, targets_dir):
    """FAIL finding -> containment proposed -> human denies -> not executed."""
    validator = _make_mock_agent(
        "validator", "validator",
        '{"finding": "FAIL", "evidence": "Password too short"}',
    )
    reporter = _make_mock_agent(
        "reporter", "reporter",
        '{"summary": "Non-compliant", "recommendation": "Fix it", "containment_action": "Isolate system", "containment_justification": "Failed check"}',
    )
    human = AgentIdentity.generate("human")
    pdp = PolicyDecisionPoint()
    audit = AuditLogger(tmp_path / "audit.jsonl")

    app = build_workflow(
        validator, reporter, pdp, audit, targets_dir,
        FakeControlStore(), human, _auto_deny,
    )
    result = await app.ainvoke({"control_id": "IA-5(1)", "target_id": "synth-web-001"})

    assert result["finding"] == "FAIL"
    assert result["containment_approved"] is False
    assert result.get("containment_executed") is None
    assert audit.entry_count() == 3  # check + report + denial


async def test_workflow_containment_human_signature_valid(tmp_path, targets_dir):
    """Verify the human's signature on the approval audit entry."""
    validator = _make_mock_agent(
        "validator", "validator",
        '{"finding": "FAIL", "evidence": "Bad"}',
    )
    reporter = _make_mock_agent(
        "reporter", "reporter",
        '{"summary": "Bad", "recommendation": "Fix", "containment_action": "Isolate", "containment_justification": "Failed"}',
    )
    human = AgentIdentity.generate("human")
    pdp = PolicyDecisionPoint()
    audit = AuditLogger(tmp_path / "audit.jsonl")

    app = build_workflow(
        validator, reporter, pdp, audit, targets_dir,
        FakeControlStore(), human, _auto_approve,
    )
    await app.ainvoke({"control_id": "IA-5(1)", "target_id": "synth-web-001"})

    # Entry 2 should be human approval (0=check, 1=report, 2=approval, 3=execution)
    approval_entry = audit.entries[2]
    assert approval_entry["agent_id"] == "human"
    assert approval_entry["action"] == "approve_containment"
    msg = f"{approval_entry['action']}:{approval_entry['resource']}:{approval_entry['detail']}"
    assert human.verify(bytes.fromhex(approval_entry["signature"]), msg.encode())


async def test_workflow_check_denied_skips_all(tmp_path, targets_dir):
    """Check denied -> no report, no containment."""
    intruder = _make_mock_agent("validator", "intruder", "should not be called")
    reporter = _make_mock_agent("reporter", "reporter", "should not be called")
    human = AgentIdentity.generate("human")
    pdp = PolicyDecisionPoint()
    audit = AuditLogger(tmp_path / "audit.jsonl")

    app = build_workflow(
        intruder, reporter, pdp, audit, targets_dir,
        FakeControlStore(), human, _auto_approve,
    )
    result = await app.ainvoke({"control_id": "IA-5(1)", "target_id": "synth-web-001"})

    assert result["check_authz_allowed"] is False
    assert result.get("containment_action") is None
    assert result.get("containment_approved") is None
    assert audit.entry_count() == 1
