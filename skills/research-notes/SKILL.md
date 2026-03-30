---
name: research-notes
description: Practical bug bounty methodology notes derived from recent public security reports and training resources.
---

# research-notes

Use this skill to guide planning and triage decisions before running tools.

## Last-30-day high-signal patterns

- Access-control flaws remain top impact class (IDOR/BOLA, role boundary bypass).
- API auth/session confusion appears in GraphQL and invite/workspace workflows.
- SSRF remains high-impact where URL fetch parameters exist (swaggerUrl-style handlers).
- Misconfiguration leaks (Prometheus /metrics, debug/internal endpoints) provide chainable recon intel.
- Upload handling gaps (SVG script payloads) continue to produce stored XSS.

## Frequent endpoint and parameter patterns

- Endpoint families: /api/v1/, /api/auth, /api/user, /internal, /graphql, /metrics, /verify-otp.
- Sensitive parameters: user_id, account_id, id, redirect_url, swaggerUrl.
- Trust-boundary headers: custom session blobs, X-Original-URL, X-Forwarded-*.

## Operational guidance for MCP AI

- Start with low-noise recon and endpoint intelligence.
- Prioritize account-boundary tests before aggressive scanning.
- Keep one active hypothesis at a time until impact is confirmed.
- Use async jobs for expensive tools to avoid MCP timeout loops.
- Prefer context-aware payload sets (top 10 per class), not brute-force payload dumps.

## Priority bug classes

- IDOR/BOLA and role boundary bypass
- auth/session handling flaws and OTP-flow bypass
- API overexposure and mass assignment patterns
- SSRF/open redirect request-routing issues
- high-confidence misconfiguration exposures

## Recommended triage sequence

1. Map live hosts and key endpoints.
2. Score endpoints and test high-priority routes first.
3. Execute access-control and auth boundary checks.
4. Run constrained vulnerability templates and targeted payloads.
5. Escalate to deeper scans only when signals are strong.

## Public references

- OWASP Top 10: https://owasp.org/Top10/
- OWASP API Security: https://owasp.org/API-Security/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- HackerOne resources: https://www.hackerone.com/
- Bugcrowd resources: https://www.bugcrowd.com/resources/
- Intigriti research blog: https://www.intigriti.com/researchers/blog
