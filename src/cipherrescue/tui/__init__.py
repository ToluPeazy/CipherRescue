"""
Layer 7 — Terminal User Interface.

Built with Textual (https://github.com/Textualize/textual).

Screen flow mirrors the session state machine (Layer 6):
    WelcomeScreen → AuthorityScreen → DeviceScreen →
    DiagnosisScreen → ActionScreen → ConfirmScreen →
    ExecuteScreen → ReportScreen

The TUI enforces the two-step confirmation requirement: the CONFIRM screen
presents the selected action, its risk level, and the backup status before
any write is permitted.

Status: STUB — screens pending implementation.
"""

from __future__ import annotations

import click


@click.command()
@click.option("--device", "-d", default="", help="Target block device path.")
@click.option("--forensic", is_flag=True, default=False,
              help="Start in forensic mode (law enforcement authority).")
@click.option("--debug", is_flag=True, default=False,
              help="Enable debug logging.")
def main(device: str, forensic: bool, debug: bool) -> None:
    """CipherRescue — FDE recovery framework."""
    import logging
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # TODO: launch Textual app
    click.echo("CipherRescue TUI — not yet implemented.")
    click.echo("SCPR engine and safety layer are operational.")
    click.echo("Run: pytest tests/ -v  to verify the diagnostic core.")


if __name__ == "__main__":
    main()
