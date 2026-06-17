"""
Unit tests — Layer 3: SecureBuffer credential zeroing (Phase 1 P0-5).
"""

from __future__ import annotations

import pytest

from cipherrescue.safety.credentials import SecureBuffer


class TestSecureBuffer:
    def test_value_accessible_before_zero(self) -> None:
        with SecureBuffer(b"secret") as buf:
            assert buf.value == b"secret"

    def test_zeroed_after_context_exit(self) -> None:
        buf = SecureBuffer(b"s3cr3t")
        buf.__enter__()
        buf.__exit__(None, None, None)
        assert buf.is_zeroed is True

    def test_zero_returns_empty_after_zeroed(self) -> None:
        buf = SecureBuffer(b"password123")
        buf.zero()
        assert buf.value == b""  # is_zeroed=True → value returns b''

    def test_double_zero_safe(self) -> None:
        buf = SecureBuffer(b"data")
        buf.zero()
        buf.zero()  # must not raise
        assert buf.is_zeroed is True

    def test_empty_buffer_safe(self) -> None:
        buf = SecureBuffer(b"")
        buf.zero()
        assert buf.is_zeroed is True

    def test_context_manager_zeros_on_exception(self) -> None:
        buf_ref: SecureBuffer | None = None
        try:
            with SecureBuffer(b"creds") as buf:
                buf_ref = buf
                raise RuntimeError("simulated error")
        except RuntimeError:
            pass
        assert buf_ref is not None
        assert buf_ref.is_zeroed is True
