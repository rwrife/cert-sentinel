# cert-sentinel

Scan hosts and endpoints for TLS/SSL certificates and warn before they expire.

## Project overview

**cert-sentinel** is a small command-line tool that connects to a list of
hosts (or reads local certificate files), inspects their TLS/SSL certificates,
and reports which ones are expiring soon, already expired, or otherwise
unhealthy (self-signed, wrong hostname, weak signature). It is designed to run
unattended — from a laptop, a CI pipeline, or a cron job — and to surface a
clear, actionable list of certificates that need attention before they cause an
outage.

## Motivation

Expired TLS certificates remain one of the most common and most avoidable
causes of production incidents. The failure mode is silent: everything works
right up until midnight on the expiry date, and then every client starts
rejecting connections. Teams often only find out when users do.

cert-sentinel exists to make certificate expiry a boring, monitored,
scheduled check instead of a 2 a.m. surprise. Point it at your endpoints once,
run it daily, and get a heads-up days or weeks before anything breaks.

## Use cases

- **SRE / ops engineers** who want a daily digest of certs expiring within N days.
- **Developers** validating that a freshly deployed endpoint serves a valid chain.
- **CI pipelines** that fail a build if any monitored endpoint is within the
  danger window.
- **Security reviews** flagging self-signed, weak, or hostname-mismatched certs.

## How to use

> Status: early scaffolding. The CLI described below is the target interface;
> see the issue backlog for implementation progress.

```bash
# Check a single host (defaults to port 443)
cert-sentinel check example.com

# Check several endpoints, warn if expiring within 30 days
cert-sentinel check example.com:443 api.example.com:8443 --warn-days 30

# Read targets from a file (one host[:port] per line)
cert-sentinel check --targets hosts.txt --warn-days 14

# Inspect a local certificate file
cert-sentinel inspect ./certs/server.pem

# JSON output for piping into other tools / alerting
cert-sentinel check --targets hosts.txt --json
```

Exit codes are designed for automation:

- `0` — all certificates healthy and outside the warning window
- `1` — one or more certificates inside the warning window or expired
- `2` — a connection/inspection error occurred

## Example commands or workflows

**Daily cron digest:**

```bash
0 8 * * * cert-sentinel check --targets /etc/cert-sentinel/hosts.txt \
  --warn-days 21 --json > /var/log/cert-sentinel.json
```

**CI gate:**

```bash
cert-sentinel check --targets endpoints.txt --warn-days 7 || {
  echo "A monitored certificate is expiring within 7 days"; exit 1;
}
```

## Current status / next milestones

- [x] Repo bootstrapped with README and PLAN
- [ ] Core certificate fetch + parse (M1)
- [ ] Expiry evaluation and warning window (M1)
- [ ] Targets file + multi-host scanning (M2)
- [ ] JSON output + machine-friendly exit codes (M2)
- [ ] Health checks: self-signed, hostname mismatch, weak signature (M3)
- [ ] Packaging and installation docs (M3)

See [PLAN.md](./PLAN.md) for scope, approach, and milestones, and the
[issue tracker](https://github.com/rwrife/cert-sentinel/issues) for the current
backlog.
