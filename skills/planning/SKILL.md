---
name: planning
description: Pre-execution planning and priority-scored task list before running tools.
---

# planning

## Objective

Create a clear, low-noise attack plan before any active testing.

## Mandatory pre-checks

- Read research-notes for current high-signal bug classes.
- Use traffic-proxy skill only after a concrete workflow hypothesis exists.

1. Scope validation
- Confirm in-scope domains/IPs.
- Confirm out-of-scope exclusions.

2. Risk tiering
- Public internet production targets: low-noise only first.
- Internal labs/CTF: broader active scans allowed.

3. Initial target profile
- Domain, ASN, technology hints, auth surface, likely API presence.

## Priority scoring model

Score each task by `impact x confidence x feasibility` (1-5 each).

- High score (60+): execute first.
- Medium (30-59): execute after first evidence.
- Low (<30): defer.

## Output contract before scanning

Produce TODO list with:
- Phase: recon / enum / vuln / verify / report
- Tool: exact tool name
- Purpose: one sentence
- Success signal: what output means progress
- Stop condition: when to stop this task

## Example TODO item

- Phase: recon
- Tool: subfinder
- Purpose: collect passive subdomains for attack surface
- Success signal: non-empty unique subdomain set
- Stop condition: duplicate-only output in 2 consecutive runs

## Execution rule

Never run exploitation until at least one strong vulnerability signal is confirmed in recon/enum.

## 2024-2026 high-signal focus

Prioritize bug classes that repeatedly show high bounty impact:
- Broken access control (IDOR/BOLA/role boundary failures)
- Authentication/session logic flaws
- API data exposure and object-level authorization issues
- Misconfiguration and sensitive endpoint exposure

## Endpoint-first planning

Before heavy scans, build a shortlist of high-value endpoint clusters:
- Account and profile endpoints
- Payment and transaction workflows
- Admin and internal API routes
- File upload and export/import endpoints

For each cluster, define:
- Expected actor (anonymous/user/admin/service)
- Expected object boundary (self-only/team/global)
- One negative test case (forbidden access)

## MCP reliability

- For long-running tools, use async flow: start_tool -> job_status -> job_result.
- Keep max 2 concurrent jobs and 1 heavy scan per target in low-noise mode.
