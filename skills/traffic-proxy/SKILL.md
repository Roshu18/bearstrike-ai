---
name: traffic-proxy
description: Request/response interception playbook for logic bug hunting with mitmproxy and OWASP ZAP.
---

# traffic-proxy

Use this skill when automated scans find a suspicious workflow but proof needs manual request mutation.

## Core tools

- mitmproxy / mitmdump: lightweight CLI interception and Python scripting.
- zaproxy / zap-cli: baseline active checks + scripting-friendly automation.

## When to use

- Session/auth workflow inconsistencies (invite, verify-otp, role change, checkout flow).
- Business logic checks where endpoint order/state matters.
- Header trust-boundary testing (custom auth blobs, forwarded headers, rewrite headers).

## Safe execution guidance

- Run proxies only on authorized targets and in scoped windows.
- Start with read-only capture before mutation.
- Keep request rate low under WAF/rate-limit pressure.
- Prefer replaying one request class at a time with strict evidence notes.

## mitmproxy quick patterns

- Capture mode: `mitmdump --listen-host 127.0.0.1 --listen-port 8081 --set flow_detail=1`
- Save flows: `mitmdump -w reports/output/<target>/mitm.flow`
- Replay selected flow IDs after controlled modifications.

## ZAP quick patterns

- Quick baseline: `zaproxy -cmd -quickurl https://<target> -quickprogress`
- Scripted run: `zap-cli quick-scan --self-contained --spider https://<target>`
- Use constrained scans first; avoid broad active scans until recon confidence is high.

## Evidence contract

For each proxy-assisted finding, capture:
- Original request and response
- Mutated request and response
- Boundary violated (auth, role, object ownership, state transition)
- Reproducible minimal steps
