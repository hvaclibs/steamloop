"""Tests for certificate handling."""

from __future__ import annotations

import ssl
from pathlib import Path

from steamloop.certs import CERT_SETS, _pem_path, create_ssl_context


def test_cert_sets_has_two_entries() -> None:
    assert len(CERT_SETS) == 2
    assert CERT_SETS[0].name == "primary"
    assert CERT_SETS[1].name == "secondary"


def test_create_ssl_context_primary() -> None:
    ctx = create_ssl_context(CERT_SETS[0])
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.maximum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE


def test_create_ssl_context_secondary() -> None:
    ctx = create_ssl_context(CERT_SETS[1])
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.maximum_version == ssl.TLSVersion.TLSv1_2


def test_primary_has_no_root_ca() -> None:
    assert CERT_SETS[0].root_ca_data is None


def test_secondary_has_root_ca() -> None:
    assert CERT_SETS[1].root_ca_data is not None


def test_pem_path_yields_a_readable_file_and_removes_it() -> None:
    # load_cert_chain() opens the path itself, so the file must be readable while the
    # context manager has yielded, and must be gone once it exits.
    with _pem_path(b"PEM") as path:
        assert Path(path).read_bytes() == b"PEM"
    assert not Path(path).exists()
