from compliance_lab.audit import AuditLogger


def test_first_entry_chains_from_genesis(tmp_path, agent_identity):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    sig = agent_identity.sign(b"control_check:t1:d1")
    entry = logger.log("validator", "control_check", "t1", "d1", sig)
    assert entry["previous_hash"] == AuditLogger.GENESIS_HASH
    assert entry["entry_hash"] != AuditLogger.GENESIS_HASH
    assert "signature" in entry


def test_second_entry_chains_from_first(tmp_path, agent_identity):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    sig1 = agent_identity.sign(b"a1")
    entry1 = logger.log("validator", "a1", "r1", "d1", sig1)
    sig2 = agent_identity.sign(b"a2")
    entry2 = logger.log("validator", "a2", "r2", "d2", sig2)
    assert entry2["previous_hash"] == entry1["entry_hash"]


def test_verify_chain_valid(tmp_path, agent_identity):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    for i in range(3):
        sig = agent_identity.sign(f"action{i}".encode())
        logger.log("validator", f"action{i}", f"r{i}", f"d{i}", sig)
    assert logger.verify_chain()


def test_verify_chain_detects_tamper(tmp_path, agent_identity):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    sig = agent_identity.sign(b"action")
    logger.log("validator", "action", "resource", "original", sig)
    # Tamper with the entry in memory
    logger._entries[0]["detail"] = "tampered"
    assert not logger.verify_chain()


def test_entry_count(tmp_path, agent_identity):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    assert logger.entry_count() == 0
    sig = agent_identity.sign(b"a")
    logger.log("validator", "a", "r", "d", sig)
    assert logger.entry_count() == 1


def test_entries_returns_copy(tmp_path, agent_identity):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    sig = agent_identity.sign(b"a")
    logger.log("validator", "a", "r", "d", sig)
    entries = logger.entries
    entries.clear()
    assert logger.entry_count() == 1  # Internal list unaffected


def test_log_persists_to_file(tmp_path, agent_identity):
    log_path = tmp_path / "audit.jsonl"
    logger = AuditLogger(log_path)
    sig = agent_identity.sign(b"a")
    logger.log("validator", "a", "r", "d", sig)
    assert log_path.exists()
    lines = log_path.read_text().strip().split("\n")
    assert len(lines) == 1
