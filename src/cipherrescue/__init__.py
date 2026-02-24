"""
CipherRescue — Bootable FDE recovery framework.

Layer structure:
    L1  boot/           Alpine Linux live image and build pipeline
    L2  detection/      SMART, entropy, and header anomaly signal extraction
    L3  safety/         WriteBlocker, BackupManager, AuditLog
    L4  plugins/        Scheme-specific recovery actions
    L5  scpr/           SCPR diagnostic engine (LP + Beasley reduction)
    L6  orchestration/  State machine and session management
    L7  tui/            Terminal User Interface

References:
    Sadeghimanesh & England (2022). ACM Commun. Comput. Algebra 56(2):76-79.
    Babatunde (2025). PhD Thesis, Coventry University.
    Babatunde, England & Sadeghimanesh (2026). arXiv:2601.14424.
"""

__version__ = "0.1.0.dev0"
__author__ = "Abiola Tolulope Babatunde"
__license__ = "GPL-3.0"
