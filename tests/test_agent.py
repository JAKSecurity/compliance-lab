from compliance_lab.agent import (
    CONTROL_IA5_1,
    REPORTER_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    build_check_prompt,
    build_report_prompt,
    parse_containment,
    parse_finding,
    parse_report,
)


def test_system_prompt_is_nonempty():
    assert len(SYSTEM_PROMPT) > 0
    assert "security" in SYSTEM_PROMPT.lower()


def test_control_text_references_password():
    assert "password" in CONTROL_IA5_1.lower()
    assert "IA-5" in CONTROL_IA5_1


def test_build_check_prompt_includes_target_data():
    target = {
        "system_id": "TEST-001",
        "password_authentication": {"compromised_password_screening": {"enabled": True}},
    }
    prompt = build_check_prompt(target, CONTROL_IA5_1)
    assert "TEST-001" in prompt
    assert "compromised_password_screening" in prompt


def test_build_check_prompt_includes_control():
    target = {"system_id": "TEST-001"}
    prompt = build_check_prompt(target, CONTROL_IA5_1)
    assert "IA-5" in prompt


def test_parse_finding_pass():
    response = '{"finding": "PASS", "evidence": "Policy meets requirements"}'
    result = parse_finding(response)
    assert result["finding"] == "PASS"
    assert result["evidence"] == "Policy meets requirements"


def test_parse_finding_fail():
    response = '{"finding": "FAIL", "evidence": "No policy configured"}'
    result = parse_finding(response)
    assert result["finding"] == "FAIL"


def test_parse_finding_with_markdown_fences():
    response = '```json\n{"finding": "PASS", "evidence": "OK"}\n```'
    result = parse_finding(response)
    assert result["finding"] == "PASS"


def test_parse_finding_malformed_returns_fail():
    result = parse_finding("This is not JSON at all")
    assert result["finding"] == "FAIL"
    assert "evidence" in result


def test_parse_finding_normalizes_case():
    response = '{"finding": "pass", "evidence": "ok"}'
    result = parse_finding(response)
    assert result["finding"] == "PASS"


def test_reporter_system_prompt_is_nonempty():
    assert len(REPORTER_SYSTEM_PROMPT) > 0
    assert "summary" in REPORTER_SYSTEM_PROMPT.lower()


def test_build_report_prompt_includes_finding():
    prompt = build_report_prompt("PASS", "Policy meets requirements", {"system_id": "T1"}, "IA-5(1)")
    assert "PASS" in prompt
    assert "Policy meets requirements" in prompt
    assert "T1" in prompt
    assert "IA-5(1)" in prompt


def test_parse_report_valid():
    response = '{"summary": "System compliant", "recommendation": "No action needed"}'
    result = parse_report(response)
    assert result["summary"] == "System compliant"
    assert result["recommendation"] == "No action needed"


def test_parse_report_with_markdown_fences():
    response = '```json\n{"summary": "OK", "recommendation": "None"}\n```'
    result = parse_report(response)
    assert result["summary"] == "OK"


def test_parse_report_malformed_returns_error():
    result = parse_report("This is not JSON at all")
    assert "summary" in result
    assert "recommendation" in result


def test_reporter_prompt_mentions_containment():
    assert "containment" in REPORTER_SYSTEM_PROMPT.lower()


def test_parse_containment_valid():
    response = '{"summary": "Non-compliant", "recommendation": "Enforce password policy", "containment_action": "Isolate system from network", "containment_justification": "Failed password policy check"}'
    result = parse_containment(response)
    assert result["containment_action"] == "Isolate system from network"
    assert result["containment_justification"] == "Failed password policy check"


def test_parse_containment_no_action():
    response = '{"summary": "Compliant", "recommendation": "No action needed"}'
    result = parse_containment(response)
    assert result["containment_action"] is None
    assert result["containment_justification"] is None


def test_parse_containment_malformed():
    result = parse_containment("Not JSON at all")
    assert result["containment_action"] is None
    assert result["containment_justification"] is None
