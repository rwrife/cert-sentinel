# cert-sentinel — Plan

## Scope

A focused CLI that answers one question well: *"Which of my TLS certificates
are expiring soon or already broken?"*

In scope:
- Fetching certificates over TLS from `host[:port]` targets.
- Inspecting local certificate files (PEM/DER).
- Evaluating expiry against a configurable warning window.
- Basic health signals: expired, self-signed, hostname mismatch, weak signature algorithm.
- Human-readable and JSON output, automation-friendly exit codes.

## Tech approach

- **Language:** Python 3.11+ (standard library `ssl` + `socket` for fetching;
  `cryptography` for robust certificate parsing).
- **Structure:**
  - `cert_sentinel/fetch.py` — establish TLS connection, retrieve peer cert chain.
  - `cert_sentinel/inspect.py` — parse certs, extract subject, SANs, validity, issuer, signature algo.
  - `cert_sentinel/evaluate.py` — apply warning window and health rules.
  - `cert_sentinel/cli.py` — argument parsing, output formatting, exit codes.
- **Output:** table for humans, `--json` for machines.
- **Testing:** pytest, with fixtures generated via a local self-signed cert helper.
- **No network services** — purely a client-side scanner.

## Milestones

- **M1 — Core check:** fetch a single host's cert, parse validity, compute days
  remaining, warn/expired classification, exit codes.
- **M2 — Scale + automation:** multi-target scanning, `--targets` file, JSON
  output, robust connection error handling.
- **M3 — Health + polish:** self-signed/hostname-mismatch/weak-signature checks,
  packaging (`pip install`), usage documentation, CI example.

## Non-goals

- Not a certificate *issuer* or ACME/Let's Encrypt client — it monitors, it does
  not renew.
- Not a full monitoring platform (no dashboards, no persistent storage, no alerting
  integrations beyond exit codes + JSON that others can consume).
- Not a general TLS scanner/pentest tool (no cipher enumeration, no protocol
  downgrade testing).
