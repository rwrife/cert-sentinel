from __future__ import annotations

import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cert_sentinel.fetch import (
    CertificateConnectionError,
    CertificateTimeoutError,
    fetch_certificate,
)


class _OneShotTLSServer:
    def __init__(self, certfile: Path, keyfile: Path) -> None:
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.bind(("127.0.0.1", 0))
        self._server_sock.listen(1)
        self.port = self._server_sock.getsockname()[1]
        self.seen_sni: str | None = None

        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))

        def _capture_sni(_sock: ssl.SSLSocket, server_name: str, _ctx: ssl.SSLContext) -> None:
            self.seen_sni = server_name

        self._context.set_servername_callback(_capture_sni)
        self._thread = threading.Thread(target=self._serve_once, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _serve_once(self) -> None:
        conn, _addr = self._server_sock.accept()
        with conn:
            with self._context.wrap_socket(conn, server_side=True):
                pass
        self._server_sock.close()

    def join(self, timeout: float = 2.0) -> None:
        self._thread.join(timeout=timeout)


def _write_self_signed_cert(tmp_path: Path, *, hostname: str) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    cert_path = tmp_path / "server.pem"
    key_path = tmp_path / "server.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_fetch_certificate_returns_leaf_certificate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hostname = "cert-fetch.test"
    cert_path, key_path = _write_self_signed_cert(tmp_path, hostname=hostname)
    server = _OneShotTLSServer(cert_path, key_path)
    server.start()

    real_create_connection = socket.create_connection

    def _redirect_connection(address: tuple[str, int], timeout: float | None = None, source_address=None):
        host, port = address
        if host == hostname:
            return real_create_connection(("127.0.0.1", port), timeout, source_address)
        return real_create_connection(address, timeout, source_address)

    monkeypatch.setattr("cert_sentinel.fetch.socket.create_connection", _redirect_connection)

    cert = fetch_certificate(hostname, port=server.port, timeout=3)

    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == hostname
    server.join()


def test_fetch_certificate_sends_sni(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    hostname = "sni-host.test"
    cert_path, key_path = _write_self_signed_cert(tmp_path, hostname=hostname)
    server = _OneShotTLSServer(cert_path, key_path)
    server.start()

    real_create_connection = socket.create_connection

    def _redirect_connection(address: tuple[str, int], timeout: float | None = None, source_address=None):
        host, port = address
        if host == hostname:
            return real_create_connection(("127.0.0.1", port), timeout, source_address)
        return real_create_connection(address, timeout, source_address)

    monkeypatch.setattr("cert_sentinel.fetch.socket.create_connection", _redirect_connection)

    fetch_certificate(hostname, port=server.port, timeout=3)
    server.join()

    assert server.seen_sni == hostname


def test_fetch_certificate_timeout_raises_typed_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_timeout(*_args, **_kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr("cert_sentinel.fetch.socket.create_connection", _raise_timeout)

    with pytest.raises(CertificateTimeoutError):
        fetch_certificate("example.com", 443, timeout=0.01)


def test_fetch_certificate_connection_failure_raises_typed_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise_gaierror(*_args, **_kwargs):
        raise socket.gaierror("name not known")

    monkeypatch.setattr("cert_sentinel.fetch.socket.create_connection", _raise_gaierror)

    with pytest.raises(CertificateConnectionError):
        fetch_certificate("does-not-resolve.test", 443)
