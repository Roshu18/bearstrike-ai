---
name: xray-suite
description: Playbook for Xray Suite scanner, crawlergo, and headless browser usage with safe request pacing.
---

# xray-suite

Read this skill before using any `xray-suite-*` tool.

## Components

1. `xray-suite-webscan`
2. `xray-suite-servicescan`
3. `xray-suite-subdomain`
4. `xray-suite-crawlergo`
5. `xray-suite-headless-browser`

## Dynamic binary resolution

The bridge script `tools/xray_suite_tools.py` resolves tools in this order:
1. Project-local bundles under `tools/bin/`
2. Windows installed binaries (when available)
3. Linux PATH binaries (`xray`, `crawlergo`, `chrome-headless-shell`, `google-chrome`, `chromium`)

## Safe usage policy

1. Start with low-noise recon and rendering first.
2. Use `xray-suite-headless-browser` and `xray-suite-crawlergo` before full webscan.
3. Keep scan scope narrow (specific hosts/URLs), not broad wildcards.
4. Respect WAF signals and reduce intensity when blocks appear.
5. Avoid aggressive brute-force against production targets without explicit authorization.

## Recommended sequence

1. Target profiling: `wafw00f`, `whatweb`, `httpx`
2. Dynamic endpoint discovery: `xray-suite-headless-browser`, `xray-suite-crawlergo`
3. Focused vulnerability scan: `xray-suite-webscan`
4. Service checks where relevant: `xray-suite-servicescan`
5. Optional domain expansion: `xray-suite-subdomain` (license/build dependent)

## No-ban scanning defaults

Bridge config uses conservative defaults in `tools/xray_suite/config.yaml`:
1. `parallel: 10`
2. `http.max_qps: 30`
3. `http.max_conns_per_host: 20`

When a target is sensitive or starts rate-limiting:
1. Reduce target scope to a single URL/path.
2. Lower concurrency/QPS further.
3. Pause between major scan phases.

## Plugin policy

The project config keeps these enabled:
1. `plugins.brute-force.enabled: true`
2. `plugins.thinkphp.enabled: true`

Runtime note:
- Some community builds can still disable certain plugins at runtime due licensing. Treat runtime output as authoritative.

## False-positive controls

1. Re-run suspected findings at least twice.
2. Confirm differences between benign and malicious payload behavior.
3. Validate real impact (not only reflected errors).
4. Exclude WAF block pages, CDN errors, and transient backend failures.
5. Save deterministic reproduction evidence for reporting.

## Commands

- `python3 tools/xray_suite_tools.py check all`
- `python3 tools/xray_suite_tools.py help all`
- `python3 tools/xray_suite_tools.py run xray-suite-webscan <target>`
- `python3 tools/xray_suite_tools.py run xray-suite-servicescan <host:port>`
- `python3 tools/xray_suite_tools.py run xray-suite-subdomain <domain>`
- `python3 tools/xray_suite_tools.py run xray-suite-crawlergo <target>`
- `python3 tools/xray_suite_tools.py run xray-suite-headless-browser <target>`

Output path:
- `reports/output/xray_suite/<target_slug>/`