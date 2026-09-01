# scripts/demo.py
"""
Compliance Lab — Slice 3 Demo
========================
Two agents. RAG-grounded control checks. Human-in-the-loop containment gate.
Identity, authorization, audit, and human approval present end-to-end.

Usage:
    uv run python scripts/demo.py
    uv run python scripts/demo.py --model mistral:7b
"""
import argparse
import asyncio
import shutil
import subprocess
import sys
from pathlib import Path

from llama_index.embeddings.ollama import OllamaEmbedding
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from compliance_lab.agents import ComplianceAgent, create_model_client
from compliance_lab.audit import AuditLogger
from compliance_lab.authz import PolicyDecisionPoint
from compliance_lab.controls import ControlStore
from compliance_lab.identity import AgentIdentity
from compliance_lab.workflow import build_workflow

PROJECT_ROOT = Path(__file__).parent.parent
TARGETS_DIR = PROJECT_ROOT / "data" / "targets"
AUDIT_DIR = PROJECT_ROOT / "data" / "audit"
CONTROLS_PATH = PROJECT_ROOT / "data" / "controls" / "nist-800-53-subset.yaml"

_OLLAMA_FALLBACK = Path.home() / "AppData" / "Local" / "Programs" / "Ollama" / "ollama.exe"

console = Console()


def _find_ollama() -> str:
    found = shutil.which("ollama")
    if found:
        return found
    if _OLLAMA_FALLBACK.exists():
        return str(_OLLAMA_FALLBACK)
    return "ollama"


def check_ollama():
    ollama_cmd = _find_ollama()
    try:
        result = subprocess.run(
            [ollama_cmd, "list"], capture_output=True, timeout=5, check=False
        )
        if result.returncode != 0:
            console.print("[bold red]ERROR:[/] Ollama is installed but not responding.")
            console.print("Start it with: [bold]ollama serve[/]")
            sys.exit(1)
    except FileNotFoundError:
        console.print("[bold red]ERROR:[/] Ollama not found. Install from https://ollama.com")
        sys.exit(1)


def check_embed_model():
    """Ensure nomic-embed-text is available for embeddings."""
    ollama_cmd = _find_ollama()
    result = subprocess.run(
        [ollama_cmd, "list"], capture_output=True, text=True, timeout=5, check=False
    )
    if "nomic-embed-text" not in result.stdout:
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Pulling nomic-embed-text embedding model..."),
            console=console,
        ) as progress:
            progress.add_task("pull", total=None)
            subprocess.run(
                [ollama_cmd, "pull", "nomic-embed-text"], timeout=300, check=True
            )


def _authz_badge(allowed: bool) -> str:
    """Return a colored Rich markup badge for authorization decisions."""
    if allowed:
        return "[bold green]ALLOWED[/]"
    return "[bold red]DENIED[/]"


def _finding_badge(finding: str) -> str:
    """Return a colored Rich markup badge for findings."""
    if finding == "PASS":
        return "[bold green]PASS[/]"
    return "[bold red]FAIL[/]"


def _sig_badge(valid: bool) -> str:
    """Return a colored Rich markup badge for signature verification."""
    if valid:
        return "[green]VALID[/]"
    return "[red]INVALID[/]"


def _build_agent_table(validator, reporter, human_id) -> Table:
    """Build a Rich table showing agent identities and permissions."""
    table = Table(title="Agent Identities", title_style="bold cyan", border_style="dim")
    table.add_column("Role", style="bold")
    table.add_column("Public Key", style="dim")
    table.add_column("Permissions")

    table.add_row(
        "[blue]validator[/]",
        validator.identity.public_key_hex()[:32] + "...",
        "control_check",
    )
    table.add_row(
        "[magenta]reporter[/]",
        reporter.identity.public_key_hex()[:32] + "...",
        "generate_report",
    )
    table.add_row(
        "[yellow]human[/]",
        human_id.public_key_hex()[:32] + "...",
        "approve_containment",
    )
    return table


def _build_audit_table(audit, identity_map) -> Table:
    """Build a Rich table showing the audit trail with signature verification."""
    table = Table(title="Audit Trail", title_style="bold cyan", border_style="dim")
    table.add_column("#", style="dim", width=3)
    table.add_column("Agent", style="bold")
    table.add_column("Action")
    table.add_column("Signature")
    table.add_column("Hash Chain", style="dim")

    for i, entry in enumerate(audit.entries):
        msg = f"{entry['action']}:{entry['resource']}:{entry['detail']}"
        agent_identity = identity_map.get(entry["agent_id"])
        if agent_identity:
            sig_valid = agent_identity.verify(bytes.fromhex(entry["signature"]), msg.encode())
            sig_str = _sig_badge(sig_valid)
        else:
            sig_str = "[dim]UNKNOWN[/]"

        # Agent color
        agent_id = entry["agent_id"]
        if agent_id == "validator":
            agent_display = "[blue]validator[/]"
        elif agent_id == "reporter":
            agent_display = "[magenta]reporter[/]"
        elif agent_id == "human":
            agent_display = "[yellow]human[/]"
        else:
            agent_display = agent_id

        # Truncated hash for chain linkage
        entry_hash = entry.get("hash", "")
        hash_display = entry_hash[:16] + "..." if len(entry_hash) > 16 else entry_hash

        table.add_row(str(i), agent_display, entry["action"], sig_str, hash_display)
    return table


async def cli_approval_callback(proposal: dict) -> bool:
    """Prompt the human at the CLI to approve or deny containment."""
    # Build the containment proposal panel content
    proposal_text = Text()
    proposal_text.append("Control:       ", style="bold")
    proposal_text.append(proposal["control_id"] + "\n")
    proposal_text.append("Target:        ", style="bold")
    proposal_text.append(proposal["target_id"] + "\n")
    proposal_text.append("Finding:       ", style="bold")
    proposal_text.append(proposal["finding"] + "\n", style="red")
    proposal_text.append("Action:        ", style="bold")
    proposal_text.append(proposal["containment_action"] + "\n")
    proposal_text.append("Justification: ", style="bold")
    proposal_text.append(proposal["containment_justification"])

    console.print()
    console.print(Panel(
        proposal_text,
        title="[bold yellow]HUMAN APPROVAL REQUIRED[/]",
        border_style="yellow",
        padding=(1, 2),
    ))

    while True:
        response = await asyncio.to_thread(
            Prompt.ask,
            "[bold yellow]Approve containment?[/]",
            choices=["approve", "deny"],
            console=console,
        )
        response = response.strip().lower()
        if response in ("approve", "yes", "y"):
            console.print("  [bold green]>>> APPROVED[/]")
            return True
        if response in ("deny", "no", "n"):
            console.print("  [bold red]>>> DENIED[/]")
            return False


async def main():
    parser = argparse.ArgumentParser(description="Compliance Lab Slice 3 Demo")
    parser.add_argument("--model", default="llama3.2:3b", help="Ollama model name")
    args = parser.parse_args()

    # Title banner
    console.print()
    console.print(Panel(
        "[bold]Two agents. RAG-grounded control checks. Human-in-the-loop containment gate.\n"
        "Identity, authorization, audit, and human approval — end-to-end.[/]",
        title="[bold cyan]Compliance Lab — Slice 3 Demo[/]",
        border_style="cyan",
        padding=(1, 2),
    ))

    # Preflight checks
    check_ollama()
    check_embed_model()

    console.print(f"  Model: [bold]{args.model}[/]")
    console.print()

    # 1. Create model client
    model_client = create_model_client(model=args.model)

    # 2. Create agents with distinct identities
    validator_id = AgentIdentity.generate("validator")
    reporter_id = AgentIdentity.generate("reporter")
    human_id = AgentIdentity.generate("human")

    validator = ComplianceAgent.create_validator(validator_id, model_client)
    reporter = ComplianceAgent.create_reporter(reporter_id, model_client)

    console.print(_build_agent_table(validator, reporter, human_id))
    console.print()

    # 3. RAG — index NIST 800-53 controls
    console.print(Rule("[bold cyan]RAG Indexing[/]"))
    embed_model = OllamaEmbedding(model_name="nomic-embed-text", base_url="http://localhost:11434")
    control_store = ControlStore.from_yaml(CONTROLS_PATH)

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Indexing NIST 800-53 controls in Qdrant (in-memory)..."),
        console=console,
    ) as progress:
        progress.add_task("indexing", total=None)
        control_store.build_index(embed_model=embed_model)

    console.print(
        f"  Indexed [bold]{control_store.control_count()}[/] controls"
    )
    console.print()

    # 4. Authorization + Audit
    pdp = PolicyDecisionPoint()
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    audit = AuditLogger(AUDIT_DIR / "slice3.jsonl")

    # 5. Build and run workflow
    console.print(Rule("[bold cyan]Phase 1: Control Check (RAG-grounded)[/]"))
    console.print("  Control: [bold]IA-5(1)[/] — Password-Based Authentication")
    console.print("  Target:  [bold]SYNTH-WEB-001[/]")
    console.print()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]Running validator agent..."),
        console=console,
    ) as progress:
        task = progress.add_task("check", total=None)
        workflow = build_workflow(
            validator, reporter, pdp, audit, TARGETS_DIR,
            control_store, human_id, cli_approval_callback,
        )
        result = await workflow.ainvoke({
            "control_id": "IA-5(1)",
            "target_id": "synth-web-001",
        })
        progress.update(task, completed=True)

    console.print()

    # 6. Check results
    console.print(f"  Check Authorization: {_authz_badge(result['check_authz_allowed'])}")
    console.print(f"  Reason: [dim]{result['check_authz_reason']}[/]")

    if result.get("finding"):
        finding = result["finding"]
        border_style = "green" if finding == "PASS" else "red"
        finding_text = Text()
        finding_text.append("Finding:  ", style="bold")
        finding_text.append(finding + "\n", style="bold green" if finding == "PASS" else "bold red")
        finding_text.append("Evidence: ", style="bold")
        finding_text.append(result["evidence"])

        console.print()
        console.print(Panel(
            finding_text,
            title=f"[bold]Control Check Result: {_finding_badge(finding)}[/]",
            border_style=border_style,
            padding=(1, 2),
        ))

    # 7. Report results
    if result.get("report_authz_allowed") is not None:
        console.print()
        console.print(Rule("[bold cyan]Phase 2: Report Generation[/]"))
        console.print(f"  Report Authorization: {_authz_badge(result['report_authz_allowed'])}")
        console.print(f"  Reason: [dim]{result['report_authz_reason']}[/]")

    if result.get("report_summary"):
        report_text = Text()
        report_text.append("Summary:        ", style="bold")
        report_text.append(result["report_summary"] + "\n")
        report_text.append("Recommendation: ", style="bold")
        report_text.append(result["report_recommendation"])

        console.print()
        console.print(Panel(
            report_text,
            title="[bold blue]Report[/]",
            border_style="blue",
            padding=(1, 2),
        ))

    # 8. Containment results
    if result.get("containment_action"):
        console.print()
        console.print(Rule("[bold cyan]Phase 3: Containment Gate[/]"))
        console.print(f"  Containment Action: [bold]{result['containment_action']}[/]")
        if result.get("containment_approved"):
            console.print(
                "  Containment: [bold green]APPROVED[/]; simulation recorded"
            )
        elif result.get("containment_approved") is False:
            console.print("  Containment: [bold red]DENIED[/] by human")
    else:
        if result.get("finding") == "PASS":
            console.print()
            console.print("  [dim]No containment needed — control check passed.[/]")

    # 9. Audit verification
    console.print()
    console.print(Rule("[bold cyan]Audit[/]"))

    chain_valid = audit.verify_chain()
    console.print(f"  Entries:    [bold]{audit.entry_count()}[/]")
    console.print(
        f"  Hash Chain: {'[bold green]VALID[/]' if chain_valid else '[bold red]BROKEN[/]'}"
    )
    console.print()

    identity_map = {
        "validator": validator.identity,
        "reporter": reporter.identity,
        "human": human_id,
    }
    console.print(_build_audit_table(audit, identity_map))

    # Final banner
    console.print()
    console.print(Rule("[bold cyan]Demo complete[/]"))
    console.print()


if __name__ == "__main__":
    asyncio.run(main())
