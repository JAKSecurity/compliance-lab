# web/server.py
"""
Compliance Lab — Live Dashboard Server
=================================
FastAPI + WebSocket server that runs the real workflow and pushes
state snapshots to the web dashboard in real time.

Usage:
    uv sync --extra web
    uv run python web/server.py
    uv run python web/server.py --model mistral:7b
"""
import argparse
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from llama_index.embeddings.ollama import OllamaEmbedding

from compliance_lab.agents import ComplianceAgent, create_model_client
from compliance_lab.audit import AuditLogger
from compliance_lab.authz import PolicyDecisionPoint
from compliance_lab.controls import ControlStore
from compliance_lab.identity import AgentIdentity
from compliance_lab.workflow import build_workflow

PROJECT_ROOT = Path(__file__).parent.parent
WEB_DIR = Path(__file__).parent
TARGETS_DIR = PROJECT_ROOT / "data" / "targets"
AUDIT_DIR = PROJECT_ROOT / "data" / "audit"
CONTROLS_PATH = PROJECT_ROOT / "data" / "controls" / "nist-800-53-subset.yaml"

_OLLAMA_FALLBACK = Path.home() / "AppData" / "Local" / "Programs" / "Ollama" / "ollama.exe"

app = FastAPI(title="Compliance Lab Dashboard")

# Default model, overridable via CLI
DEFAULT_MODEL = "llama3.2:3b"

# Node → active agent mapping
NODE_AGENTS = {
    "load_target": None,
    "check_phase": "validator",
    "report_phase": "reporter",
    "containment_phase": "human",
    "execute_containment": "validator",
}

# Node → authz info for snapshot reconstruction
AUTHZ_INFO = {
    "check_phase": ("validator", "control_check"),
    "report_phase": ("reporter", "generate_report"),
    "containment_phase": ("human", "approve_containment"),
}

# State keys that map to authz allowed/reason
AUTHZ_STATE_KEYS = {
    "check_phase": ("check_authz_allowed", "check_authz_reason"),
    "report_phase": ("report_authz_allowed", "report_authz_reason"),
}


def _find_ollama() -> str:
    found = shutil.which("ollama")
    if found:
        return found
    if _OLLAMA_FALLBACK.exists():
        return str(_OLLAMA_FALLBACK)
    return "ollama"


def _check_ollama():
    ollama_cmd = _find_ollama()
    try:
        result = subprocess.run(
            [ollama_cmd, "list"], capture_output=True, timeout=5, check=False
        )
        if result.returncode != 0:
            print("ERROR: Ollama is installed but not responding. Start it with: ollama serve")
            sys.exit(1)
    except FileNotFoundError:
        print("ERROR: Ollama not found. Install from https://ollama.com")
        sys.exit(1)


def build_audit_snapshot(audit: AuditLogger) -> list[dict]:
    """Build audit entries for the client, matching the static JSON format."""
    return [
        {
            "agent_id": e["agent_id"],
            "action": e["action"],
            "resource": e["resource"],
            "detail": e["detail"],
            "signature_present": bool(e.get("signature")),
            "entry_hash": e["entry_hash"],
            "previous_hash": e["previous_hash"],
        }
        for e in audit.entries
    ]


def build_authz_decision(node_name: str, target_id: str, state: dict) -> dict | None:
    """Reconstruct authz decision from node name and accumulated state."""
    if node_name not in AUTHZ_INFO:
        return None
    agent_id, action = AUTHZ_INFO[node_name]

    allowed_key, reason_key = AUTHZ_STATE_KEYS.get(node_name, (None, None))
    if allowed_key and allowed_key in state:
        allowed = state[allowed_key]
        reason = state.get(reason_key, "")
    else:
        # containment_phase or default
        allowed = True
        reason = "Policy allows action"

    return {
        "agent_id": agent_id,
        "action": action,
        "resource": target_id,
        "allowed": allowed,
        "reason": reason,
    }


def safe_state(state: dict) -> dict:
    """Filter state to JSON-serializable values only."""
    out = {}
    for k, v in state.items():
        if isinstance(v, (str, int, float, bool, type(None))):
            out[k] = v
        elif isinstance(v, dict):
            out[k] = safe_state(v)
        elif isinstance(v, list):
            out[k] = v
        else:
            out[k] = str(v)
    return out


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()

    try:
        # Wait for start command
        msg = await ws.receive_json()
        if msg.get("action") != "start":
            await ws.send_json({"type": "error", "message": "Expected start action"})
            return

        model = msg.get("model", DEFAULT_MODEL)
        control_id = msg.get("control_id", "IA-5(1)")
        target_id = msg.get("target_id", "synth-web-001")

        # Create agents
        model_client = create_model_client(model=model)
        validator_id = AgentIdentity.generate("validator")
        reporter_id = AgentIdentity.generate("reporter")
        human_id = AgentIdentity.generate("human")

        validator = ComplianceAgent.create_validator(validator_id, model_client)
        reporter = ComplianceAgent.create_reporter(reporter_id, model_client)

        # Send agent identities to client
        await ws.send_json({
            "type": "agents",
            "agents": {
                "validator": {"key": validator_id.public_key_hex()[:16] + "..."},
                "reporter": {"key": reporter_id.public_key_hex()[:16] + "..."},
                "human": {"key": human_id.public_key_hex()[:16] + "..."},
            },
        })

        # RAG indexing
        await ws.send_json({"type": "status", "message": "Indexing NIST 800-53 controls..."})
        embed_model = OllamaEmbedding(
            model_name="nomic-embed-text", base_url="http://localhost:11434"
        )
        control_store = ControlStore.from_yaml(CONTROLS_PATH)
        control_store.build_index(embed_model=embed_model)
        await ws.send_json({
            "type": "status",
            "message": f"Indexed {control_store.control_count()} controls",
        })

        # Authz + audit
        pdp = PolicyDecisionPoint()
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        audit = AuditLogger(AUDIT_DIR / "live.jsonl")

        # Approval callback — pauses workflow until client responds via WebSocket
        async def ws_approval_callback(proposal: dict) -> bool:
            await ws.send_json({"type": "containment_proposal", "proposal": proposal})
            while True:
                resp = await ws.receive_json()
                action = resp.get("action")
                if action == "approve":
                    return True
                if action == "deny":
                    return False

        # Build and stream workflow
        workflow = build_workflow(
            validator, reporter, pdp, audit, TARGETS_DIR,
            control_store, human_id, ws_approval_callback,
        )

        accumulated = {"control_id": control_id, "target_id": target_id}

        async for chunk in workflow.astream(
            {"control_id": control_id, "target_id": target_id}
        ):
            for node_name, update in chunk.items():
                if node_name.startswith("__"):
                    continue

                accumulated.update(update)
                authz = build_authz_decision(node_name, target_id, accumulated)

                snapshot = {
                    "phase": node_name,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "active_node": node_name,
                    "active_agent": NODE_AGENTS.get(node_name),
                    "authz_decision": authz,
                    "workflow_state": safe_state(accumulated),
                    "audit_entries": build_audit_snapshot(audit),
                }
                await ws.send_json({"type": "snapshot", "snapshot": snapshot})

        # Final "complete" snapshot
        await ws.send_json({
            "type": "snapshot",
            "snapshot": {
                "phase": "complete",
                "timestamp": datetime.now(UTC).isoformat(),
                "active_node": None,
                "active_agent": None,
                "authz_decision": None,
                "workflow_state": safe_state(accumulated),
                "audit_entries": build_audit_snapshot(audit),
            },
        })
        await ws.send_json({"type": "complete"})

    except WebSocketDisconnect:
        return
    except Exception as exc:  # noqa: BLE001 - report workflow failures to the local client
        try:
            await ws.send_json({"type": "error", "message": str(exc)})
        except RuntimeError:
            return


# Static files — must come after WebSocket route definition
app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="static")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compliance Lab Live Dashboard Server")
    parser.add_argument("--model", default="llama3.2:3b", help="Ollama model name")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    DEFAULT_MODEL = args.model
    _check_ollama()
    print(f"Compliance Lab Dashboard — http://{args.host}:{args.port}")
    print(f"Model: {args.model}")
    uvicorn.run(app, host=args.host, port=args.port)
