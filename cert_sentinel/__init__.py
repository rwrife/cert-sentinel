"""cert-sentinel package."""

from .fetch import (
    CertificateConnectionError,
    CertificateFetchError,
    CertificateTimeoutError,
    fetch_certificate,
    fetch_certificates,
)

__all__ = [
    "CertificateFetchError",
    "CertificateTimeoutError",
    "CertificateConnectionError",
    "fetch_certificate",
    "fetch_certificates",
]
