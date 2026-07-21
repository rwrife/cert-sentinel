"""Certificate inspection helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass(slots=True)
class CertificateInfo:
    """Normalized certificate fields used by evaluation and output layers."""

    subject_common_name: str | None
    subject_alt_names: list[str]
    not_before: datetime
    not_after: datetime
    issuer: str
    signature_algorithm: str | None


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _extract_subject_common_name(cert: x509.Certificate) -> str | None:
    common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return common_names[0].value if common_names else None


def _extract_subject_alt_names(cert: x509.Certificate) -> list[str]:
    try:
        san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []

    san_values: list[str] = []
    for name in san_extension.value:
        value = getattr(name, "value", name)
        san_values.append(str(value))
    return san_values


def _extract_signature_algorithm(cert: x509.Certificate) -> str | None:
    try:
        hash_algorithm = cert.signature_hash_algorithm
    except Exception:
        hash_algorithm = None

    if hash_algorithm is not None:
        return hash_algorithm.name

    oid_name = getattr(cert.signature_algorithm_oid, "_name", None)
    if oid_name:
        return str(oid_name)
    return cert.signature_algorithm_oid.dotted_string


def inspect_certificate(cert: x509.Certificate) -> CertificateInfo:
    """Extract normalized certificate fields for downstream evaluation."""

    not_before_raw = getattr(cert, "not_valid_before_utc", None)
    if not_before_raw is None:
        not_before_raw = cert.not_valid_before

    not_after_raw = getattr(cert, "not_valid_after_utc", None)
    if not_after_raw is None:
        not_after_raw = cert.not_valid_after

    not_before = _as_utc(not_before_raw)
    not_after = _as_utc(not_after_raw)

    return CertificateInfo(
        subject_common_name=_extract_subject_common_name(cert),
        subject_alt_names=_extract_subject_alt_names(cert),
        not_before=not_before,
        not_after=not_after,
        issuer=cert.issuer.rfc4514_string(),
        signature_algorithm=_extract_signature_algorithm(cert),
    )
