import json
import re
from pathlib import Path

import yaml

SYSTEM_PROMPT = """You are a security control validator for the Compliance Lab system.
Your job is to evaluate whether a target system meets a specific security control requirement.

You will receive:
1. A control requirement (from NIST 800-53)
2. A target system configuration

Respond with EXACTLY this JSON format and nothing else:
{"finding": "PASS", "evidence": "Brief explanation"}

Use "PASS" if the system meets the requirement, "FAIL" if it does not.
Do not include any text outside the JSON object."""

_CONTROLS_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "controls" / "nist-800-53-subset.yaml"
)


def _bundled_control_text(control_id: str) -> str:
    """Load a control from the generated, pinned OSCAL subset."""
    with _CONTROLS_PATH.open() as controls_file:
        data = yaml.safe_load(controls_file)
    for control in data["controls"]:
        if control["id"] == control_id:
            return control["text"]
    raise RuntimeError(f"Bundled control is absent: {control_id}")


CONTROL_IA5_1 = _bundled_control_text("IA-5(1)")


def build_check_prompt(target_data: dict, control_text: str) -> str:
    """Build the user prompt for a control check."""
    target_yaml = yaml.dump(target_data, default_flow_style=False)
    return (
        f"Evaluate the following target system against the control requirement.\n\n"
        f"## Control Requirement\n{control_text}\n\n"
        f"## Target System Configuration\n```yaml\n{target_yaml}```\n\n"
        f"Respond with your finding as JSON."
    )


def parse_finding(response_text: str) -> dict:
    """Parse LLM response into a finding dict. Handles JSON with or without markdown fences."""
    text = response_text.strip()
    # Strip markdown code fences
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:])
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
        text = text.strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
            except json.JSONDecodeError:
                return {"finding": "FAIL", "evidence": f"Unparseable response: {text[:200]}"}
        else:
            return {"finding": "FAIL", "evidence": f"No JSON in response: {text[:200]}"}

    finding = str(parsed.get("finding", "")).upper()
    if finding not in ("PASS", "FAIL"):
        finding = "FAIL"
    return {"finding": finding, "evidence": parsed.get("evidence", "No evidence provided")}


REPORTER_SYSTEM_PROMPT = """You are a security compliance reporter for the Compliance Lab system.
Your job is to take a control validation finding and produce a structured summary report.

You will receive:
1. A control ID and its description
2. A target system configuration
3. The validation finding (PASS or FAIL) and evidence

If the finding is PASS, respond with this JSON format:
{"summary": "One-paragraph summary", "recommendation": "Recommended next steps"}

If the finding is FAIL, respond with this JSON format that includes a containment action:
{"summary": "One-paragraph summary", "recommendation": "Recommended next steps", "containment_action": "Specific containment action to take", "containment_justification": "Why this containment is necessary"}

Do not include any text outside the JSON object."""


def build_report_prompt(
    finding: str, evidence: str, target_data: dict, control_id: str
) -> str:
    """Build the user prompt for a report generation."""
    target_yaml = yaml.dump(target_data, default_flow_style=False)
    return (
        f"Generate a compliance report for the following control validation.\n\n"
        f"## Control\n{control_id}\n\n"
        f"## Target System\n```yaml\n{target_yaml}```\n\n"
        f"## Validation Result\nFinding: {finding}\nEvidence: {evidence}\n\n"
        f"Respond with your report as JSON."
    )


def parse_report(response_text: str) -> dict:
    """Parse LLM response into a report dict. Same fence-stripping as parse_finding."""
    text = response_text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:])
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
        text = text.strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
            except json.JSONDecodeError:
                return {
                    "summary": f"Unparseable response: {text[:200]}",
                    "recommendation": "Manual review required",
                }
        else:
            return {
                "summary": f"No JSON in response: {text[:200]}",
                "recommendation": "Manual review required",
            }

    return {
        "summary": parsed.get("summary", "No summary provided"),
        "recommendation": parsed.get("recommendation", "No recommendation provided"),
    }


def parse_containment(response_text: str) -> dict:
    """Extract containment action from a report response. Returns None fields if not present."""
    text = response_text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:])
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
        text = text.strip()

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group())
            except json.JSONDecodeError:
                return {"containment_action": None, "containment_justification": None}
        else:
            return {"containment_action": None, "containment_justification": None}

    return {
        "containment_action": parsed.get("containment_action"),
        "containment_justification": parsed.get("containment_justification"),
    }
