#!/usr/bin/env python3
"""Generate a safe, evidence-oriented manual test plan; it performs no network requests."""
from __future__ import annotations
import argparse, json
from pathlib import Path

BASE = [
    ("Scope", "Confirm written authorization, assets, test window, rate limits, and emergency contact."),
    ("Asset inventory", "Record domains, subdomains, APIs, environments, and ownership; remove anything outside scope."),
    ("Transport", "Review HTTPS redirects, certificate chain, HSTS, cookie flags, CORS, and security headers."),
    ("Error handling", "Use harmless invalid inputs and confirm errors do not disclose secrets, stack traces, or internal paths."),
    ("Logging", "Confirm security events are logged without tokens, passwords, or personal data."),
]
MODULES = {
    "web": [("Input validation", "Review output encoding and server-side validation in HTML, JSON, URL, and template contexts."), ("CSRF", "Verify state-changing actions require an appropriate anti-CSRF control."), ("File handling", "Review upload type, size, storage, download authorization, and execution prevention.")],
    "api": [("Authorization", "Use separate test accounts to verify horizontal and vertical access control on every endpoint."), ("API schema", "Check unknown fields, mass assignment, excessive data exposure, pagination, and rate limits."), ("Tokens", "Review token scope, expiry, rotation, revocation, and leakage in URLs or logs.")],
    "auth": [("Login", "Review throttling, account lockout behavior, MFA, recovery, and session rotation."), ("Session", "Verify logout, idle timeout, absolute timeout, fixation resistance, and cookie scope."), ("Recovery", "Verify reset links are short-lived, single-use, non-enumerating, and bound to the right account.")],
    "graphql": [("GraphQL controls", "Review introspection policy, depth/complexity limits, batching, resolver authorization, and field exposure.")],
    "upload": [("Upload isolation", "Verify allowlists, content validation, random names, size limits, malware workflow, and storage outside executable web roots.")],
    "business": [
        ("Workflow integrity", "Map every state transition and verify the server rejects skipped, reversed, or repeated steps."),
        ("Object ownership", "Use two test accounts and confirm every read, update, download, and delete checks ownership server-side."),
        ("Replay and idempotency", "Repeat a harmless request with a test record and verify payments, invitations, coupons, and actions are not duplicated."),
        ("Limits and pricing", "Check quantity, currency, discount, inventory, pagination, and time boundaries with non-production data."),
        ("Concurrency", "With written approval, run a small controlled parallel test against disposable records and verify atomic state changes."),
        ("Approval and roles", "Verify approval, refund, export, moderation, and administrative actions require the intended role and separation of duties."),
        ("Abuse resistance", "Review rate limits, quotas, invitation limits, trial conversion, and resource exhaustion controls without stress testing production."),
    ],
}

def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a manual security test plan without network activity")
    parser.add_argument("--type", action="append", choices=sorted(MODULES), default=["web"], help="application area; repeatable")
    parser.add_argument("--out", default="manual-plan.md")
    args = parser.parse_args()
    rows = BASE[:]
    for kind in dict.fromkeys(args.type): rows.extend(MODULES[kind])
    lines = ["# Manual Security Test Plan", "", "> This plan performs no scans and no exploit actions. Execute only with written authorization.", "", "| Area | Safe verification objective | Status | Evidence |", "|---|---|---|---|"]
    for area, objective in rows: lines.append(f"| {area} | {objective} | TODO | |")
    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    Path(str(args.out).removesuffix(".md") + ".json").write_text(json.dumps({"areas": [{"area": a, "objective": o, "status": "TODO"} for a, o in rows]}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"تم إنشاء {args.out}")
    return 0

if __name__ == "__main__": raise SystemExit(main())
