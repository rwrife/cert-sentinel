"""TLS certificate fetching utilities."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass

from cryptography import x509


@dataclass(slots=True)
class _Endpoint:
    host: str
    port: int


class CertificateFetchError(Exception):
    """Base class for certificate fetch failures."""

    def __init__(self, host: str, port: int, message: str) -> None:
        super().__init__(f"{message} ({host}:{port})")
        self.host = host
        self.port = port


class CertificateTimeoutError(CertificateFetchError):
    """Raised when certificate fetch exceeds configured timeout."""


class CertificateConnectionError(CertificateFetchError):
    """Raised when socket/TLS connection cannot be established."""


DEFAULT_TIMEOUT_SECONDS = 10.0


def _validate_endpoint(host: str, port: int) -> _Endpoint:
    if not host or not isinstance(host, str):
        raise ValueError("host must be a non-empty string")
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError("port must be an integer in range 1..65535")
    return _Endpoint(host=host, port=port)


def fetch_certificates(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> list[x509.Certificate]:
    """Fetch peer certificate(s) from a TLS endpoint.

    Returns a list of parsed ``cryptography.x509.Certificate`` objects.
    On Python 3.11, the stdlib SSL API only exposes the leaf peer certificate,
    so the returned list currently contains the leaf certificate.
    """

    endpoint = _validate_endpoint(host, port)
    if timeout <= 0:
        raise ValueError("timeout must be > 0")

    context = ssl.create_default_context()
    # We are inspecting endpoint certificates; verification is handled later.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((endpoint.host, endpoint.port), timeout=timeout) as tcp_sock:
            with context.wrap_socket(tcp_sock, server_hostname=endpoint.host) as tls_sock:
                der_leaf = tls_sock.getpeercert(binary_form=True)
                if not der_leaf:
                    raise CertificateFetchError(endpoint.host, endpoint.port, "No peer certificate received")
                leaf_cert = x509.load_der_x509_certificate(der_leaf)
                return [leaf_cert]
    except socket.timeout as exc:
        raise CertificateTimeoutError(endpoint.host, endpoint.port, "Connection timed out") from exc
    except TimeoutError as exc:
        raise CertificateTimeoutError(endpoint.host, endpoint.port, "Connection timed out") from exc
    except (socket.gaierror, OSError, ssl.SSLError) as exc:
        raise CertificateConnectionError(endpoint.host, endpoint.port, f"TLS connection failed: {exc}") from exc


def fetch_certificate(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> x509.Certificate:
    """Fetch the leaf certificate for a TLS endpoint."""

    return fetch_certificates(host=host, port=port, timeout=timeout)[0]
