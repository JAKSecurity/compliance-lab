import pytest

from compliance_lab.targets import get_target_by_id, load_target


def test_load_target(targets_dir):
    target = load_target(targets_dir / "synth-web-001.yaml")
    assert target["system_id"] == "SYNTH-WEB-001"
    password_authentication = target["password_authentication"]
    assert password_authentication["compromised_password_screening"]["enabled"] is True
    assert password_authentication["storage"]["salted_key_derivation_function"] is True


def test_get_target_by_id(targets_dir):
    target = get_target_by_id(targets_dir, "synth-web-001")
    assert target["system_id"] == "SYNTH-WEB-001"


def test_get_target_missing_raises(targets_dir):
    with pytest.raises(FileNotFoundError, match="nonexistent"):
        get_target_by_id(targets_dir, "nonexistent")
