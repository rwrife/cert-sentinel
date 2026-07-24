from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_sentinel.cli import main
from cert_sentinel.evaluate import EvaluationResult
from cert_sentinel.fetch import CertificateFetchError
from cert_sentinel.inspect import CertificateInfo


def _cert_info(not_after: datetime) -> CertificateInfo:
    return CertificateInfo(
        subject_common_name="example.test",
        subject_alt_names=["example.test"],
        not_before=datetime.now(UTC) - timedelta(days=1),
        not_after=not_after,
        issuer="CN=Example Issuer",
        signature_algorithm="sha256",
    )


def test_check_single_host_prints_one_row_and_exit_zero(monkeypatch, capsys) -> None:
    fake_cert = object()

    monkeypatch.setattr("cert_sentinel.cli.fetch_certificate", lambda host, port=443: fake_cert)
    monkeypatch.setattr(
        "cert_sentinel.cli.inspect_certificate",
        lambda cert: _cert_info(datetime(2026, 2, 1, tzinfo=UTC)),
    )
    monkeypatch.setattr(
        "cert_sentinel.cli.evaluate",
        lambda cert_info, warn_days=30: EvaluationResult(status="ok", days_remaining=31),
    )

    exit_code = main(["check", "example.com"])

    assert exit_code == 0
    output = capsys.readouterr().out
    assert "TARGET" in output
    assert "example.com" in output
    assert "ok" in output
    assert "31" in output


def test_check_multiple_hosts_and_warn_days_are_honored(monkeypatch, capsys) -> None:
    warn_days_seen: list[int] = []

    def _fake_fetch(host: str, port: int = 443):
        return f"{host}:{port}"

    def _fake_inspect(_cert):
        return _cert_info(datetime(2026, 3, 1, tzinfo=UTC))

    def _fake_evaluate(cert_info, warn_days=30):
        warn_days_seen.append(warn_days)
        return EvaluationResult(status="ok", days_remaining=22)

    monkeypatch.setattr("cert_sentinel.cli.fetch_certificate", _fake_fetch)
    monkeypatch.setattr("cert_sentinel.cli.inspect_certificate", _fake_inspect)
    monkeypatch.setattr("cert_sentinel.cli.evaluate", _fake_evaluate)

    exit_code = main(["check", "a.test", "b.test:8443", "--warn-days", "7"])

    assert exit_code == 0
    assert warn_days_seen == [7, 7]

    output = capsys.readouterr().out
    assert "a.test" in output
    assert "b.test:8443" in output



def test_check_returns_exit_one_for_warning_or_expired(monkeypatch, capsys) -> None:
    statuses = iter([
        EvaluationResult(status="warning", days_remaining=5),
        EvaluationResult(status="expired", days_remaining=-1),
    ])

    monkeypatch.setattr("cert_sentinel.cli.fetch_certificate", lambda host, port=443: object())
    monkeypatch.setattr(
        "cert_sentinel.cli.inspect_certificate",
        lambda cert: _cert_info(datetime(2026, 1, 20, tzinfo=UTC)),
    )
    monkeypatch.setattr("cert_sentinel.cli.evaluate", lambda cert_info, warn_days=30: next(statuses))

    exit_code = main(["check", "warn.test", "expired.test"])

    assert exit_code == 1
    output = capsys.readouterr().out
    assert "warning" in output
    assert "expired" in output



def test_check_returns_exit_two_when_any_target_errors(monkeypatch, capsys) -> None:
    def _fake_fetch(host: str, port: int = 443):
        if host == "bad.test":
            raise CertificateFetchError(host, port, "TLS failed")
        return object()

    monkeypatch.setattr("cert_sentinel.cli.fetch_certificate", _fake_fetch)
    monkeypatch.setattr(
        "cert_sentinel.cli.inspect_certificate",
        lambda cert: _cert_info(datetime(2026, 5, 1, tzinfo=UTC)),
    )
    monkeypatch.setattr(
        "cert_sentinel.cli.evaluate",
        lambda cert_info, warn_days=30: EvaluationResult(status="ok", days_remaining=60),
    )

    exit_code = main(["check", "ok.test", "bad.test"])

    assert exit_code == 2
    output = capsys.readouterr().out
    assert "ok.test" in output
    assert "bad.test" in output
    assert "error" in output
