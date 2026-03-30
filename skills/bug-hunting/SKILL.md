---
name: bug-hunting
description: End-to-end bug bounty phase flow for BearStrike AI.
---

# bug-hunting

Use this flow for authorized bug bounty targets.

## State machine

RECON -> ENUM -> VULN -> VERIFY -> REPORT

## Rules

- Stay in scope at every step.
- Stop noisy scans when WAF is detected and switch to low-rate mode.
- Confirm findings manually before report generation.

## Recommended sequence

1. recon skill to map hosts and services.
2. pentest-tools skill to choose matching tools per target type.
3. exploitation skill only after strong signals.
4. reporting skill to produce final markdown package.

## Bug-hunt loop (efficient mode)

Use this loop to reduce noise and token burn:
1. Build endpoint shortlist by business impact.
2. Test authorization boundaries first.
3. Validate one strong signal to completion.
4. Expand only if evidence quality remains high.

## Where bugs are often found

Focus checks on:
- ID fields in REST/JSON APIs
- GraphQL object queries and mutations
- Mobile/web API parity gaps
- Multi-step flows (cart -> payment -> refund)
- Export/report endpoints leaking cross-tenant data

## Quality gate

Do not continue to next hypothesis until current one has:
- baseline response,
- altered request response,
- clear impact statement.
