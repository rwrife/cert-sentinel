"""Command-line interface for cert-sentinel."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Sequence

from cert_sentinel.evaluate import evaluate
from cert_sentinel.fetch import CertificateFetchError, fetch_certificate
from cert_sentinel.inspect import inspect_certificate

DEFAULT_PORT = 443


@dataclass(slots=True)
class CheckRow:
    target: str
    status: str
    days_remaining: int | None
    expiry_date: str | None
    error: str | None = None


def _parse_target(target: str) -> tuple[str, int]:
    if not target:
        raise ValueError("target must be a non-empty string")

    if ":" not in target:
        return target, DEFAULT_PORT

    host, port_text = target.rsplit(":", 1)
    if not host:
        raise ValueError(f"invalid target {target!r}: host is empty")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError(f"invalid target {target!r}: port must be an integer") from exc
    if not (1 <= port <= 65535):
        raise ValueError(f"invalid target {target!r}: port must be in range 1..65535")
    return host, port


def _format_expiry(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    return dt.date().isoformat()


def _render_table(rows: list[CheckRow]) -> str:
    headers = ["TARGET", "STATUS", "DAYS", "EXPIRY"]
    table_rows: list[list[str]] = []

    for row in rows:
        days = "-" if row.days_remaining is None else str(row.days_remaining)
        expiry = row.expiry_date or "-"
        if row.error:
            expiry = f"error: {row.error}"
        table_rows.append([row.target, row.status, days, expiry])

    widths = [len(h) for h in headers]
    for table_row in table_rows:
        for i, value in enumerate(table_row):
            widths[i] = max(widths[i], len(value))

    def _fmt(values: list[str]) -> str:
        return "  ".join(value.ljust(widths[i]) for i, value in enumerate(values))

    separator = "  ".join("-" * width for width in widths)
    lines = [_fmt(headers), separator]
    lines.extend(_fmt(row) for row in table_rows)
    return "\n".join(lines)


def _run_check(targets: Sequence[str], warn_days: int) -> tuple[list[CheckRow], int]:
    rows: list[CheckRow] = []
    saw_error = False
    saw_unhealthy = False

    for target in targets:
        try:
            host, port = _parse_target(target)
            cert = fetch_certificate(host, port=port)
            cert_info = inspect_certificate(cert)
            evaluation = evaluate(cert_info, warn_days=warn_days)

            status = evaluation.status
            if status != "ok":
                saw_unhealthy = True

            rendered_target = f"{host}:{port}" if port != DEFAULT_PORT else host
            rows.append(
                CheckRow(
                    target=rendered_target,
                    status=status,
                    days_remaining=evaluation.days_remaining,
                    expiry_date=_format_expiry(cert_info.not_after),
                )
            )
        except (CertificateFetchError, ValueError) as exc:
            saw_error = True
            rows.append(CheckRow(target=target, status="error", days_remaining=None, expiry_date=None, error=str(exc)))

    if saw_error:
        exit_code = 2
    elif saw_unhealthy:
        exit_code = 1
    else:
        exit_code = 0

    return rows, exit_code


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cert-sentinel", description="Check TLS certificate freshness")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="check certificate status for one or more hosts")
    check_parser.add_argument("targets", nargs="+", help="host or host:port targets")
    check_parser.add_argument(
        "--warn-days",
        type=int,
        default=30,
        help="warning threshold in days before expiry (default: 30)",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "check":
        rows, exit_code = _run_check(args.targets, warn_days=args.warn_days)
        print(_render_table(rows))
        return exit_code

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
