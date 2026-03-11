# CipherRescue™

*SCPR-Based Bootable FDE Recovery and Diagnostic Framework*

[![CI](https://github.com/ToluPeazy/cipherrescue/actions/workflows/ci.yml/badge.svg)](https://github.com/ToluPeazy/cipherrescue/actions)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue)](https://www.python.org)
[![ORCID](https://img.shields.io/badge/ORCID-0000--0001--7186--1092-green)](https://orcid.org/0000-0001-7186-1092)

---

## Overview

CipherRescue is an open-source bootable diagnostic and recovery framework for Full Disk
Encryption (FDE) failures. It applies the **Set Covering Problem with Reasons (SCPR)**
as a formal optimisation method to identify the minimal set of root-cause reasons
sufficient to explain a given pattern of observed failure signals on an encrypted drive.

The system boots independently of the host OS, detects the encryption scheme in use
(BitLocker, LUKS1/2, VeraCrypt, Opal SED), performs non-destructive diagnostics, and
guides operators through evidence-grade recovery workflows with a full audit trail.

---

## Motivation

Every once in a while, devices become corrupt due to encryption failures or bad memory
issues. Identifying the root cause — the *reasons* for failure — is crucial in
determining the type of solution that works. This is the motivation for CipherRescue:
a formal, reproducible approach to a problem that has historically required manual
expertise and vendor-specific tooling.

---

## Features

- **SCPR Diagnostic Engine** — applies Set Covering Problem with Reasons for root-cause
  optimisation across observed failure signals
- **Bootable ISO** — Alpine Linux-based live image; boots from USB or CD on any x86-64
  machine, independent of the compromised OS
- **Multi-Scheme Support** — BitLocker, LUKS1, LUKS2, VeraCrypt, Opal SED
- **Safety-First Architecture** — write-blocking, mandatory backup before any write
  operation, and HMAC-chained audit logs
- **ILP Solver** — exact optimality-certifying solution via HiGHS branch-and-bound
- **Beasley Reduction** — structural preprocessing to reduce instance complexity before
  solving
- **Evidence-Grade Audit Trail** — signed JSON audit log exportable for corporate
  incident response

---

## Installation

```bash
# Clone the repository
git clone https://github.com/ToluPeazy/cipherrescue.git
cd cipherrescue

# Create virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install with dev dependencies
pip install -e ".[dev]"
```

---

## Quick Start

```python
from cipherrescue.scpr import SCPRSolver, load_benchmark_instance

# Load a benchmark instance
instance = load_benchmark_instance("path/to/instance.pkl")

# Run the SCPR diagnostic engine
solver = SCPRSolver()
result = solver.solve(instance)

print(result.optimal_reasons)      # Minimal covering set of reasons
print(result.objective_value)      # Optimal cost
print(result.is_optimal)           # Optimality certificate
```

---

## Architecture

CipherRescue is structured as a layered framework:

| Layer | Component | Purpose |
|-------|-----------|---------|
| 1 | Device Enumerator | Detects drives, partitions, health signals |
| 2 | Detection Engine | Identifies encryption scheme and failure indicators |
| 3 | Safety & Audit | Write-blocker, backup manager, HMAC audit log |
| 4 | Plugin Layer | Scheme-specific recovery operations |
| 5 | SCPR Engine | ILP-based root-cause optimisation |
| 6 | Orchestration | Deterministic state machine coordinating the workflow |
| 7 | TUI | Terminal user interface for operator interaction |

---

## Testing

```bash
pytest                        # Run all tests
pytest tests/unit/            # Unit tests only
pytest --cov=src/cipherrescue # With coverage report
```

CI runs on Python 3.11 and 3.12 on every push.

---

## Citation

If you use CipherRescue in your research, please cite:

```bibtex
@software{babatunde2026cipherrescue,
  author  = {Babatunde, Abiola Tolulope},
  title   = {CipherRescue: SCPR-Based Cryptographic Storage Failure Diagnosis System},
  year    = {2026},
  url     = {https://github.com/ToluPeazy/cipherrescue},
  license = {Apache-2.0},
  orcid   = {https://orcid.org/0000-0001-7186-1092}
}
```

**Related Research:**

```bibtex
@article{babatunde2025scpr,
  author  = {Babatunde, Abiola Tolulope and England, Matthew and Sadeghimanesh, AmirHosein},
  title   = {Optimising Cylindrical Algebraic Coverings for use in Satisfiability Modulo
             Theories by Solving a Set Covering Problem with Reasons},
  journal = {Discrete Optimization},
  year    = {2025},
  note    = {Submitted},
  url     = {https://arxiv.org/abs/2601.14424}
}
```

---

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Submitting SCPR instance datasets to the benchmark library
- Code contributions and bug fixes
- Plugin development for new encryption schemes
- Feature requests and issue reporting

---

## License

Copyright 2026 Abiola Tolulope Babatunde

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this project except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See [LICENSE](LICENSE) for full license text.

---

## Trademark

CipherRescue™ is a trademark of Abiola Tolulope Babatunde.

---

## Acknowledgments

This project is developed at Coventry University as part of doctoral research on the
Set Covering Problem with Reasons (SCPR) and its application to cryptographic storage
failure diagnosis.

**Supervisors:** Prof. Matthew England, Dr. AmirHosein Sadeghimanesh

The SCPR benchmark dataset is available on Zenodo:
[doi:10.5281/zenodo.15326494](https://doi.org/10.5281/zenodo.15326494)

---

## Contact

**Maintainer:** Abiola Tolulope Babatunde
**ORCID:** [0000-0001-7186-1092](https://orcid.org/0000-0001-7186-1092)
**GitHub:** [@ToluPeazy](https://github.com/ToluPeazy)
**Email:** babatundea@coventry.ac.uk

---

*Built with formal optimisation methods for the cryptographic storage community.*
