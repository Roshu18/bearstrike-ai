---
name: reporting
description: Reporting standards for single bug, full pentest, and recon-only outputs.
---

# reporting

## Report folder structure

All reports must be saved under:

reports/output/<target_slug>/<YYYY-MM-DD>/run_<HHMMSS>/

Artifacts:
- report.md
- findings.json
- metadata.json

## Report type selection

### 1) Single bug report
Use when one confirmed high-quality issue exists.

Required sections:
- Title
- Severity
- Affected endpoint
- Reproduction steps
- PoC request
- Impact
- Remediation

### 2) Full pentest report
Use for multi-phase assessments.

Required sections:
- Executive summary
- Scope and methodology
- Attack surface summary
- Findings by severity
- Remediation roadmap
- Appendix (commands/artifacts)

### 3) Recon report
Use when no exploitable bug is confirmed but strong intel exists.

Required sections:
- Target map (hosts/services)
- Technology stack
- Exposed surfaces
- Suspicious signals for follow-up
- Next-step recommendations

## Quality checklist

Before finalizing, ensure:
- Every finding has reproducible evidence.
- No finding is only a scanner claim without validation.
- Severity aligns with demonstrated impact.
- Fix guidance is concrete and actionable.

## Exploit write-up quality

If exploit details are included, provide:
- Preconditions
- Step-by-step execution
- Clean expected output
- Safe rollback/mitigation notes

## Evidence package standard

Each finding should include:
- request/response pair (baseline and exploit case)
- environment and account prerequisites
- deterministic reproduction steps
- impact in business language (data scope, privilege level, workflow effect)

## False-positive rejection section

When closing as false positive, document:
- hypothesis tested
- why signal was non-security
- artifact proving rejection
