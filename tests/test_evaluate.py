from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cert_sentinel.evaluate import evaluate
from cert_sentinel.inspect import CertificateInfo


def _cert_info(*, not_before: datetime, not_after: datetime) -> CertificateInfo:
    return CertificateInfo(
        subject_common_name="example.test",
        subject_alt_names=["example.test"],
        not_before=not_before,
        not_after=not_after,
        issuer="CN=Example Issuer",
        signature_algorithm="sha256",
    )


def test_evaluate_returns_status_and_days_remaining() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    info = _cert_info(
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=90),
    )

    result = evaluate(info, warn_days=30, now=now)

    assert result.status == "ok"
    assert result.days_remaining == 90


def test_evaluate_marks_warning_when_expiry_is_within_window() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    info = _cert_info(
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=7),
    )

    result = evaluate(info, warn_days=30, now=now)

    assert result.status == "warning"
    assert result.days_remaining == 7


def test_evaluate_marks_expired_when_not_after_has_passed() -> None:
    now = datetime(2026, 1, 10, tzinfo=UTC)
    info = _cert_info(
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(hours=1),
    )

    result = evaluate(info, warn_days=30, now=now)

    assert result.status == "expired"
    assert result.days_remaining == -1


def test_evaluate_marks_not_yet_valid_distinctly() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    info = _cert_info(
        not_before=now + timedelta(hours=12),
        not_after=now + timedelta(days=30),
    )

    result = evaluate(info, warn_days=30, now=now)

    assert result.status == "not_yet_valid"
    assert result.days_remaining == 30


@pytest.mark.parametrize("warn_days", [-1, 3.5])
def test_evaluate_rejects_invalid_warn_days(warn_days: int) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    info = _cert_info(
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=10),
    )

    with pytest.raises(ValueError):
        evaluate(info, warn_days=warn_days, now=now)
