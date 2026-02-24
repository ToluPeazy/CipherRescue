# Contributing to CipherRescue

Thank you for your interest in contributing.

## Before You Start

Please read [SECURITY.md](SECURITY.md) before contributing any
security-sensitive code. All contributors must agree that their
contributions are licensed under GPL-3.0.

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/cipherrescue.git
cd cipherrescue
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Verify the baseline passes:

```bash
pytest tests/ -v
ruff check src/ tests/
```

## Contribution Areas

The project is structured by layer. The most useful contributions
right now, in priority order:

1. **Layer 2 — Detection Engine** (`src/cipherrescue/detection/`)
   SMART attribute parsing, entropy sampling, header signature checks.
   Pure Python, no special hardware required for unit testing.

2. **Layer 3 — BackupManager** (`src/cipherrescue/safety/`)
   `dd`/`ddrescue` wrapper, SHA-256 verification, BackupToken issuance.

3. **Layer 4 — Plugins** (`src/cipherrescue/plugins/`)
   Concrete implementations of `LUKS2Plugin`, `BitLockerPlugin`,
   `VeraCryptPlugin`. Requires access to test drive images.

4. **Layer 6 — Orchestration** (`src/cipherrescue/orchestration/`)
   Full state machine implementation.

5. **Layer 7 — TUI** (`src/cipherrescue/tui/`)
   Textual screens following the state machine flow.

## Code Standards

- All code must pass `ruff check` and `ruff format`.
- All public functions and classes require docstrings.
- New functionality requires unit tests in `tests/unit/`.
- Type annotations are required (`mypy --strict` must pass).

## Plugin Contributions

Community plugins must:
- Subclass `SchemePlugin` and implement all abstract methods.
- Route ALL writes through `self._wb.write_gate()` (Contract C4).
- Include a `plugin.json` manifest.
- Be submitted with a GPG-signed commit.

Plugins that bypass the WriteBlocker will not be accepted.

## Commit Messages

Follow the conventional commits format:

```
feat(scpr): add LP-based variable fixing for SCPR reduction
fix(safety): correct hash ordering in AuditLog chain
test(detection): add LUKS2 header signature unit tests
docs: update plugin contract documentation
```

## Pull Requests

- Open a PR against the `develop` branch.
- All CI checks must pass.
- At least one maintainer review is required before merge.
- Security-sensitive PRs require two reviews.
