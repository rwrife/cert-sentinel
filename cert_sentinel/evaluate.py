"""Certificate evaluation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from cert_sentinel.inspect import CertificateInfo


@dataclass(slots=True)
class EvaluationResult:
    """Classification result for a certificate relative to a warning window."""

    status: str
    days_remaining: int


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def evaluate(
    cert_info: CertificateInfo,
    warn_days: int = 30,
    *,
    now: datetime | None = None,
) -> EvaluationResult:
    """Evaluate certificate freshness against ``warn_days``.

    Statuses:
    - ``ok``: currently valid and outside warning window
    - ``warning``: currently valid but expiring in fewer than ``warn_days`` days
    - ``expired``: ``not_after`` has passed
    - ``not_yet_valid``: current time is before ``not_before``
    """

    if not isinstance(warn_days, int) or warn_days < 0:
        raise ValueError("warn_days must be a non-negative integer")

    current_time = _as_utc(now or datetime.now(UTC))
    not_before = _as_utc(cert_info.not_before)
    not_after = _as_utc(cert_info.not_after)

    days_remaining = (not_after - current_time).days

    if current_time < not_before:
        status = "not_yet_valid"
    elif current_time >= not_after:
        status = "expired"
    elif days_remaining < warn_days:
        status = "warning"
    else:
        status = "ok"

    return EvaluationResult(status=status, days_remaining=days_remaining)
