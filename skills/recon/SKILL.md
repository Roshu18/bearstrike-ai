---
name: recon
description: Recon workflow for domain, DNS, host, and web surface mapping.
---

# recon

## Workflow

1. Subdomain discovery
- subfinder -d <domain>
- amass enum -d <domain>

2. DNS mapping
- dnsenum <domain>
- theHarvester -d <domain> -b all

3. Service discovery
- nmap -sV -Pn <target>

4. Web fingerprinting
- httpx <target>
- whatweb <target>
- wafw00f <target>

5. Content discovery
- ffuf/gobuster/dirsearch
- katana for URL crawl

## Exit criteria

- Live hosts list, open ports, tech stack, WAF status, and high-value endpoints recorded.

## High-yield endpoint map strategy

Collect endpoints from three sources and merge:
1. Live probing and crawl (httpx/katana)
2. Historical archives (gau/waybackurls)
3. Parameter discovery (arjun)

Tag endpoints quickly by risk:
- auth-critical: login, reset, token, oauth, session
- object-critical: /user/, /account/, /invoice/, /order/, /api/v*/id
- admin/internal: /admin, /internal, /debug, /graphql

## Recon stop condition

Stop broad discovery when either condition is true:
- 20+ high-value unique endpoints are mapped, or
- Two consecutive recon runs produce only duplicates.

Then switch to verification-focused testing.
