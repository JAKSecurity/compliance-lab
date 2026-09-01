from compliance_lab.authz import AuthzRequest, PolicyDecisionPoint


def test_allow_validator_control_check():
    pdp = PolicyDecisionPoint()
    decision = pdp.authorize(AuthzRequest("validator", "control_check", "any-target"))
    assert decision.allowed is True
    assert decision.reason


def test_deny_unknown_agent():
    pdp = PolicyDecisionPoint()
    decision = pdp.authorize(AuthzRequest("intruder", "control_check", "any-target"))
    assert decision.allowed is False
    assert "intruder" in decision.reason


def test_deny_unauthorized_action():
    pdp = PolicyDecisionPoint()
    decision = pdp.authorize(AuthzRequest("validator", "delete_system", "any-target"))
    assert decision.allowed is False
    assert "delete_system" in decision.reason


def test_allow_reporter_generate_report():
    pdp = PolicyDecisionPoint()
    decision = pdp.authorize(AuthzRequest("reporter", "generate_report", "any-target"))
    assert decision.allowed is True
    assert decision.reason


def test_deny_reporter_control_check():
    pdp = PolicyDecisionPoint()
    decision = pdp.authorize(AuthzRequest("reporter", "control_check", "any-target"))
    assert decision.allowed is False
    assert "control_check" in decision.reason


def test_deny_validator_generate_report():
    pdp = PolicyDecisionPoint()
    decision = pdp.authorize(AuthzRequest("validator", "generate_report", "any-target"))
    assert decision.allowed is False
    assert "generate_report" in decision.reason


def test_allow_human_approve_containment():
    pdp = PolicyDecisionPoint()
    decision = pdp.authorize(AuthzRequest("human", "approve_containment", "any-target"))
    assert decision.allowed is True
    assert decision.reason


def test_deny_human_control_check():
    pdp = PolicyDecisionPoint()
    decision = pdp.authorize(AuthzRequest("human", "control_check", "any-target"))
    assert decision.allowed is False
    assert "control_check" in decision.reason


def test_deny_validator_approve_containment():
    pdp = PolicyDecisionPoint()
    decision = pdp.authorize(AuthzRequest("validator", "approve_containment", "any-target"))
    assert decision.allowed is False
    assert "approve_containment" in decision.reason
