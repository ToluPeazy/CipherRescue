# CipherRescue

**Bootable FDE recovery framework with LP-optimal diagnostic engine**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Status: Pre-Release](https://img.shields.io/badge/status-pre--release-orange.svg)]()
[![Build](https://github.com/ToluPeazy/cipherrescue/actions/workflows/ci.yml/badge.svg)]()

---

CipherRescue is an open-source bootable tool for diagnosing and recovering
Full Disk Encryption (FDE) failures across BitLocker, LUKS2, VeraCrypt, and
TCG Opal. It is the **first system to apply the Set Covering Problem with
Reasons (SCPR)** to cryptographic storage failure diagnosis, producing
LP-optimal, reason-annotated diagnoses where LP dual variables serve as
interpretable evidence weights.

> **Research context.** CipherRescue is the third domain application of
> SCPR, following its genesis in SMT solving
> (Sadeghimanesh & England, 2022) and application to Functional Enrichment
> Analysis (Babatunde, 2025). The mathematical foundations are established
> in Babatunde, England & Sadeghimanesh (2026, arXiv:2601.14424).

---

## Architecture

CipherRescue is organised into seven formal layers:

| Layer | Name | Responsibility |
|-------|------|----------------|
| L1 | Boot Environment | Alpine Linux live image; write-isolated initramfs |
| L2 | Detection Engine | SMART, entropy, header anomaly signal extraction |
| L3 | Safety & Audit Layer | WriteBlocker, BackupManager, tamper-evident AuditLog |
| L4 | Plugin Layer | Scheme-specific recovery actions (sandboxed) |
| L5 | SCPR Diagnostic Engine | LP + Beasley reduction; optimal failure mode coverage |
| L6 | Orchestration Engine | State machine; session management |
| L7 | TUI | Operator-facing terminal interface |

---

## Security Model

- **Write isolation.** All target block devices remain read-only at the OS
  level (Alpine initramfs policy) and at the application level (WriteBlocker).
  No write can reach a target device without a cryptographic backup token.
- **Authenticated recovery only.** CipherRescue requires the same credentials
  a legitimate owner would use. It provides no bypass capability.
- **Forensic mode.** Hash-chained, append-only audit log with authority
  declaration. Supports ACPO/SWGDE-compatible evidence preservation.
- **Plugin sandboxing.** Community plugins run in restricted network
  namespaces with seccomp profiles. GPG-signed plugins only (by default).

---

## Status

This repository is in **pre-release development**. The mathematical
specification is complete (see `docs/spec/`). Implementation is in progress,
layer by layer. Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

**Layer completion:**

- [ ] L1 — Boot environment (Docker build pipeline)
- [ ] L2 — Detection engine
- [ ] L3 — Safety & audit layer
- [ ] L4 — Plugin layer (LUKS2, BitLocker, VeraCrypt stubs)
- [ ] L5 — SCPR diagnostic engine ← *current focus*
- [ ] L6 — Orchestration engine
- [ ] L7 — TUI

---

## Installation (development)

```bash
git clone https://github.com/ToluPeazy/cipherrescue.git
cd cipherrescue
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

**Runtime dependencies (on target live image):**

```
cryptsetup  >= 2.4
dislocker   >= 0.7.3
mdadm       >= 4.1
smartmontools >= 7.3
```

---

## Running tests

```bash
pytest tests/ -v --cov=src/cipherrescue
```

---

## Building the ISO

> Requires Docker. The build pipeline produces a reproducible ISO via
> `SOURCE_DATE_EPOCH` propagation and `apk` package hash verification.

```bash
./scripts/build_iso.sh
```

Verify the build:

```bash
./scripts/verify_iso.sh cipherrescue.iso
```

---

## Documentation

Full mathematical specification (50+ pages):

- [`docs/spec/CipherRescue_Comprehensive_Specification.pdf`](docs/spec/)

---

## Intellectual Property

| Asset | Licence |
|-------|---------|
| Source code | GPL-3.0 |
| Name "CipherRescue" | Trademark pending (UK Class 9, EUIPO) |
| Papers and datasets | CC-BY-4.0 |

Any fork **must** rename the project. The official signed ISO bearing the
CipherRescue trademark is the canonical, auditable release.

---

## Citation

If you use CipherRescue or its SCPR diagnostic formulation in academic work,
please cite:

```bibtex
@unpublished{babatunde2026arxiv,
  author = {Babatunde, Abiola Tolulope and England, Matthew and
            Sadeghimanesh, AmirHosein},
  title  = {Optimising Cylindrical Algebraic Coverings for Use in {SMT}
            by Solving a {Set Covering Problem with Reasons}},
  year   = {2026},
  note   = {arXiv:2601.14424. Submitted to Journal of Discrete
            Optimisation (Elsevier)}
}
```

---

## Contact

Dr Abiola Tolulope Babatunde — lead researcher and maintainer.
