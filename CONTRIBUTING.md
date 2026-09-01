# Contributing

Compliance Lab is a small research prototype.  Contributions should preserve its synthetic-data boundary and make the security properties no stronger than the implementation supports.

## Development setup

```bash
uv sync --frozen --extra web --group dev
uv run pytest -q
uv run ruff check .
```

Python 3.11 through 3.13 is supported.  The checked-in `.python-version` selects Python 3.13 for local development.

## Contribution rules

- Use only public sources and fabricated `SYNTH-*` target data.
- Do not submit credentials, personal data, client data, controlled information, employer material, or private assessment results.
- Keep containment behavior simulated unless the project explicitly changes scope and documents a safe execution boundary.
- Do not edit `data/controls/nist-800-53-subset.yaml` by hand.  Rebuild it with `scripts/build_control_subset.py` and document any source-version change.
- Add meaningful tests for behavior changes and run the test and lint commands before opening a pull request.
- Describe security limitations and failure behavior directly.  Avoid claims of compliance or production enforcement.
