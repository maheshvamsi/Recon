# Bug Bounty Recon-to-Jackpot Methodology

Two-script pipeline: `recon.sh` builds the attack surface → `jackpot.sh` confirms vulnerabilities.

## recon.sh — Attack Surface Generation

```
Input: -u <domain> or -l <domains_file>
Output: recon_<domain>_<timestamp>/  (or recon_multi_<timestamp>/)
```

### Step 1 — Subdomain Enumeration (parallel, per domain)
| Tool | Source | Output |
|---|---|---|
| subfinder | Passive DNS, cert streams | `.temp/subfinder.txt` |
| assetfinder | CRT logs, ASN lookups | `.temp/assetfinder.txt` |
| crtsh | Certificate Transparency logs | `.temp/crtsh.txt` |
| chaos (optional) | ProjectDiscovery CDN | `.temp/chaos.txt` |
| findomain (optional) | API aggregator | `.temp/findomain.txt` |

Merge: `sort -u .temp/*.txt → all_subdomains.txt`

### Step 2 — HTTP Probing
`httpx` on all subdomains → `httpx_results.txt` (status codes, titles, tech stack, content-length)

Extract live URLs → `live_subdomains.txt`

### Step 3 — Historical URL Collection (parallel)
| Tool | Scope | URLs collected |
|---|---|---|
| gau --subs | root domains | Historical params, endpoints from Wayback/OTX/AlienVault |
| waybackurls | clean domains | Wayback Machine snapshots |
| katana (optional) | live subdomains | Active crawl of current pages |

Merge → `urls_raw.txt` → uro filter → `urls_cleaned.txt`

### Step 4 — Parameter & Attack Surface Extraction
| Output | Filter | Purpose |
|---|---|---|
| `parameterized_urls.txt` | `grep "\?.*=" urls_cleaned.txt` | All URLs with query params — **jackpot input** |
| `juicy_params.txt` | High-value param names (id, redirect, file, token, etc.) | IDOR/redirect/LFI targets |
| `high_priority.txt` | Keywords in path (admin, api, dev, dashboard) | High-value entry points |
| `attack_surface.txt` | Copy of juicy_params | Full parameter scope |
| `interesting_paths.txt` | Path keywords from httpx results | Admin panels, APIs |
| `forbidden_pages.txt` | HTTP 403 from httpx | Bypass candidates |
| `error_pages.txt` | HTTP 500 from httpx | Injection surface |
| `domains_clean.txt` | Hostnames without scheme/path | Domain list for later filtering |

### Output Files (jackpot required in **bold**)

| Required | File | Lines (typical large scope) |
|---|---|---|
| **✓** | `parameterized_urls.txt` | 10k–500k |
| **✓** | `live_subdomains.txt` | 100–5k |
| **✓** | `urls_cleaned.txt` | 50k–1M |
| opt | `juicy_params.txt` | 5k–100k |
| opt | `high_priority.txt` | 1k–20k |
| opt | `attack_surface.txt` | 5k–100k |
| opt | `httpx_results.txt` | 100–5k |
| opt | `interesting_paths.txt` | 10–500 |
| opt | `forbidden_pages.txt` | 5–200 |
| opt | `error_pages.txt` | 1–50 |
| opt | `katana_urls.txt` | 10k–200k |
| opt | `domains_clean.txt` | 100–5k |

---

## jackpot.sh — Vulnerability Confirmation

```
Input: -f <recon_directory> from recon.sh
Output: jackpot_results_<timestamp>/
```

### Phase 1–2: Preflight
- Tool availability (gf, qsreplace, httpx, curl, nuclei)
- Validate required files exist
- Extract in-scope domains (for third-party URL filtering)

### Phase 3: GF Pattern Scanning (13 vuln classes)
Scans `parameterized_urls.txt` / `urls_cleaned.txt` with gf patterns:

| Severity | Pattern | What it finds |
|---|---|---|
| P1 | aws, takeovers | Exposed keys, unclaimed subdomains |
| P2 | cors, ssti, sqli, tokens | CORS misconfigs, template injection, SQLi params, secrets |
| P3 | idor, lfi, xss, rce, debug, firebase, s3-buckets | Parameter-based vuln candidates |

Redirect-specific: gf redirect → param-name whitelist → `redirect_clean.txt`

### Phase 4: Open Redirect Blast Chain
1. Injects 12 payload patterns (evil.com, protocol-relative, double-encode, etc.) into `redirect_clean.txt` via qsreplace
2. **Single httpx batch** (was 12 sequential runs) — 1 network pass for all payloads
3. Parses Location header, checks for `evil.com` in 301/302/303/307/308
4. Output: `redirect_confirmed.txt`

### Phase 5: 403 Bypass Chain
1. Collects 403s from `httpx_results.txt` + `forbidden_pages.txt`
2. Per URL: 18 path techniques (`..;/`, `//`, `%2e%2e%2f`, etc.) + 13 header techniques (`X-Forwarded-For`, `X-Original-URL`, etc.)
3. FP filter: skips 0-byte and same-size-as-baseline 200s
4. Output: `403_bypass_confirmed.txt` (200s) + `403_bypass_suspicious.txt` (3xx behavior changes)

### Phase 6: Response Analysis (zero HTTP requests)
Mines existing `httpx_results.txt` for:
- 200s with sensitive keywords (admin, config, secret, .git, etc.)
- 301/302 redirects
- 500 errors (injection surface)
- Juicy page titles (Admin, Login, Dashboard, Grafana, etc.)
- Tech stack fingerprints
- Non-standard ports

### Phase 6b: 403 Bypass Verification (soft-404 detection)
1. Fetches response body of each bypass-confirmed URL
2. Checks for soft-404 / WAF patterns (404, not found, access denied, forbidden, blocked, etc.)
3. Output: `403_bypass_real.txt` (confirmed real) + `403_bypass_suspect_soft404.txt` (likely WAF page)

### Phase 7: SSTI Auto-Verification
1. Filters GF ssti.txt to in-scope domains (blocks third-party FPs like adobe.com)
2. Samples 100 URLs max
3. Injects `{{7*7777777}}` via qsreplace (evaluates to `54444439` — unique, won't appear in normal HTML)
4. Parallel curl probes, checks response for `54444439` AND absence of raw `{{7*7777777}}` (excludes echo-back FPs)
5. Output: `ssti_confirmed.txt`

### Phase 8: CORS Auto-Verification
1. Filters GF cors.txt to in-scope domains
2. Sends `Origin: https://evil.com` header via curl
3. Checks for `Access-Control-Allow-Origin` reflection or wildcard `*`
4. Output: `cors_confirmed.txt`

### Phase 9: Nuclei Auto-Verification
1. Samples 500 URLs per pattern from rce, sqli, ssti, xss, lfi, idor
2. Runs nuclei with `-severity medium,high,critical` (parallel, max 3 simultaneous)
3. Output: `nuclei_confirmed.txt`

### Summary & Prioritisation
- **P1** (immediate): Open redirects, RCE, nuclei verified, takeovers, AWS keys
- **P2** (high): 403 bypasses, SSTI, SQLi, tokens, CORS
- **P3** (medium): IDOR, LFI, XSS, debug pages, firebase, S3 buckets
- **CDN check**: dig +short CNAME on all findings to flag CloudFront/Cloudflare/Akamai-mirrored hosts
- **Action plan**: step-by-step guidance mapped to actual output files

---

## Data Flow Diagram

```
recon.sh                              jackpot.sh
─────────                             ──────────
domains                               Phase 1-2: Validate
  │                                    │
  ├─ all_subdomains.txt               │
  │    │                              │
  │    ├─ httpx_results.txt ──────────┼── Phase 6 (Response Analysis)
  │    │    │                         │      │
  │    │    ├─ live_subdomains.txt ───┼── Phase 5 (403 Bypass)
  │    │    │                         │      │
  │    │    └─ forbidden_pages.txt ───┤      │
  │    │                              │      │
  │    └─ urls_cleaned.txt            │      └─ Phase 6b (403 Verify)
  │         │                         │
  │         ├─ parameterized_urls.txt─┼── Phase 3 (GF Scan)
  │         │                         │      │
  │         │                         │      ├─ Phase 4 (Redirect)
  │         │                         │      ├─ Phase 7 (SSTI)
  │         │                         │      ├─ Phase 8 (CORS)
  │         │                         │      └─ Phase 9 (Nuclei)
  │         │                         │
  │         └─ juicy_params.txt ──────┤
  │         └─ high_priority.txt ─────┤
  │         └─ attack_surface.txt ────┤
  │                                  │
  └─ domains_clean.txt ──────────────┼── Scope filter
```

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Scope filter for SSTI/CORS | GF catches third-party URLs (adobe.com, powerbi.com) from wayback data; testing those wastes API calls and creates FPs |
| Single httpx batch for redirects | 12 sequential httpx runs = 12x TCP connection overhead; one batch file = 1 network pass |
| `{{7*7777777}}` → `54444439` | `49` (from `{{7*7}}`) appears naturally in HTML (ages, version numbers, page counts); `54444439` doesn't |
| Soft-404 body check on bypasses | WAFs return 200 with "blocked" page — same size/body every time; body keyword check filters these out |
| Sampling on large inputs | SSTI samples 100 URLs, nuclei samples 500 — keeps runtime predictable on datasets with 100k+ URLs |
| Resume checkpoints | Script can take 15-30 mins with nuclei; markers prevent re-running completed phases after Ctrl-C |
| `$'\033'` not `'\033'` for colors | Plain `echo` outputs literal `\033` text (not ANSI codes) when colors are stored as literal strings |
