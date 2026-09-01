from pathlib import Path

import yaml


def load_target(target_path: Path) -> dict:
    """Load a synthetic target from a YAML file."""
    with open(target_path) as f:
        return yaml.safe_load(f)


def get_target_by_id(targets_dir: Path, target_id: str) -> dict:
    """Load a target by ID. Raises FileNotFoundError if not found."""
    target_path = targets_dir / f"{target_id.lower()}.yaml"
    if not target_path.exists():
        raise FileNotFoundError(f"Target '{target_id}' not found at {target_path}")
    return load_target(target_path)
