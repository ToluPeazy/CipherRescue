"""
Layer 3 — Safety & Audit: SecureBuffer.

Provides mlock-backed, explicitly zeroable credential buffers per spec §7.2.

mlock() is attempted on Linux; on platforms where it is unavailable (Windows,
macOS without entitlement, CI without CAP_IPC_LOCK), the buffer degrades
gracefully to an in-memory bytearray with explicit zeroing only.
"""

from __future__ import annotations

import ctypes
import logging
import sys
from types import TracebackType

logger = logging.getLogger(__name__)

_MLOCK_AVAILABLE = False

if sys.platform.startswith("linux"):
    try:
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
        _MLOCK_AVAILABLE = True
    except OSError:
        pass


def _mlock(addr: int, length: int) -> bool:
    """Call mlock(2). Returns True on success."""
    if not _MLOCK_AVAILABLE:
        return False
    ret = _libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))  # type: ignore[union-attr]
    return ret == 0


def _munlock(addr: int, length: int) -> None:
    """Call munlock(2). Silent on failure."""
    if _MLOCK_AVAILABLE:
        _libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))  # type: ignore[union-attr]


class SecureBuffer:
    """
    A bytearray-backed credential buffer that:
      - Attempts mlock() to prevent the contents being swapped to disk.
      - Zeros memory explicitly via ctypes.memset on release/close.

    Usage::

        with SecureBuffer(passphrase.encode()) as buf:
            plugin.authenticate(device, buf.value)
        # buffer is zeroed here

    After close() or __exit__, buf.value returns b'' and is_zeroed is True.
    """

    def __init__(self, data: bytes) -> None:
        self._buf = bytearray(data)
        self._length = len(self._buf)
        self.is_zeroed = False

        if self._length > 0:
            addr = (ctypes.c_char * self._length).from_buffer(self._buf)
            locked = _mlock(ctypes.addressof(addr), self._length)
            if not locked and _MLOCK_AVAILABLE:
                logger.warning(
                    "SecureBuffer: mlock failed for %d-byte buffer "
                    "(CAP_IPC_LOCK may be required)",
                    self._length,
                )

    @property
    def value(self) -> bytes:
        """Return the current buffer contents, or b'' if the buffer is zeroed."""
        if self.is_zeroed:
            return b""
        return bytes(self._buf)

    def zero(self) -> None:
        """Explicitly zero the buffer via ctypes.memset and munlock."""
        if self.is_zeroed:
            return
        if self._length > 0:
            addr = (ctypes.c_char * self._length).from_buffer(self._buf)
            ctypes.memset(addr, 0, self._length)
            _munlock(ctypes.addressof(addr), self._length)
        self.is_zeroed = True

    def __enter__(self) -> SecureBuffer:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.zero()

    def __del__(self) -> None:
        self.zero()
