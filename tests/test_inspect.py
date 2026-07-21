from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cert_sentinel.inspect import inspect_certificate


def _build_certificate(*, subject: x509.Name, san_entries: list[x509.GeneralName] | None) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=10))
    )
    if san_entries is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    return builder.sign(private_key=key, algorithm=hashes.SHA256())


def test_inspect_certificate_extracts_requested_fields() -> None:
    cert = _build_certificate(
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")]),
        san_entries=[x509.DNSName("example.test"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))],
    )

    info = inspect_certificate(cert)

    assert info.subject_common_name == "example.test"
    assert info.subject_alt_names == ["example.test", "127.0.0.1"]
    assert info.not_before.tzinfo == UTC
    assert info.not_after.tzinfo == UTC
    assert "CN=example.test" in info.issuer
    assert isinstance(info.signature_algorithm, str)
    assert info.signature_algorithm


def test_inspect_certificate_handles_missing_optional_fields() -> None:
    cert = _build_certificate(
        subject=x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "No CN Org")]),
        san_entries=None,
    )

    info = inspect_certificate(cert)

    assert info.subject_common_name is None
    assert info.subject_alt_names == []
    assert info.not_before.tzinfo == UTC
    assert info.not_after.tzinfo == UTC
