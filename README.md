# Bug Bounty Recon & Jackpot Pipeline

Two scripts that automate the full recon-to-vulnerability-confirmation workflow for bug bounty programs.

```
recon.sh  ──>  attack surface  ──>  jackpot.sh  ──>  confirmed findings
```

---

## Required Tools

### Core (must be installed)
| Tool | Install | Used by |
|---|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | recon |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | `go install github.com/tomnomnom/assetfinder@latest` | recon |
| [httpx](https://github.com/projectdiscovery/httpx) | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | recon + jackpot |
| [gau](https://github.com/lc/gau) | `go install github.com/lc/gau/v2/cmd/gau@latest` | recon |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | `go install github.com/tomnomnom/waybackurls@latest` | recon |
| [jq](https://jqlang.github.io/jq/) | `apt install jq` | recon |
| [curl](https://curl.se/) | `apt install curl` | recon + jackpot |
| [uro](https://github.com/s0md3v/uro) | `pip install uro` | recon |
| [gf](https://github.com/tomnomnom/gf) | `go install github.com/tomnomnom/gf@latest` | jackpot |
| [qsreplace](https://github.com/tomnomnom/qsreplace) | `go install github.com/tomnomnom/qsreplace@latest` | jackpot |
| [nuclei](https://github.com/projectdiscovery/nuclei) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | jackpot |
| [dig](https://en.wikipedia.org/wiki/Dig_(command)) | `apt install dnsutils` | jackpot (CDN check) |

### Optional (better coverage)
| Tool | Install | Used by |
|---|---|---|
| [chaos](https://github.com/projectdiscovery/chaos-client) | `go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest` | recon |
| [findomain](https://github.com/Findomain/Findomain) | [releases](https://github.com/Findomain/Findomain/releases) | recon |
| [katana](https://github.com/projectdiscovery/katana) | `go install github.com/projectdiscovery/katana/cmd/katana@latest` | recon |
| [parallel](https://www.gnu.org/software/parallel/) | `apt install parallel` | jackpot |

---

## recon.sh — Attack Surface Generation

Collects subdomains, probes live hosts, gathers historical URLs, and extracts the attack surface.

### Usage

```bash
# Single domain
./recon.sh -u example.com

# Multiple domains from a file
./recon.sh -l domains.txt

# Skip JS extraction (faster)
./recon.sh -u example.com --skip-js

# Resume an interrupted scan
./recon.sh -u example.com --resume
```

### What it does

```
1. Subdomain enumeration (parallel)
   ├── subfinder, assetfinder, crt.sh
   ├── chaos, findomain (if installed)
   └── merge → all_subdomains.txt

2. HTTP probing
   └── httpx → httpx_results.txt + live_subdomains.txt

3. URL collection
   ├── gau --subs (historical params)
   ├── waybackurls (wayback machine)
   └── katana (active crawl, if installed)

4. URL cleaning
   └── uro → urls_cleaned.txt

5. Attack surface extraction
   ├── parameterized_urls.txt  ← URLs with ?param=
   ├── juicy_params.txt        ← High-value params
   ├── high_priority.txt       ← Admin/api/dev paths
   ├── attack_surface.txt      ← Full param scope
   ├── forbidden_pages.txt     ← HTTP 403 endpoints
   ├── interesting_paths.txt   ← Dashboard/swagger etc.
   └── error_pages.txt         ← HTTP 500 endpoints
```

### Output directory structure

```
recon_example.com_2026-06-25_08-48-42/
├── all_subdomains.txt          # All discovered subdomains
├── live_subdomains.txt         # URLs that responded (http:// / https://)
├── httpx_results.txt           # Full httpx probe output
├── urls_cleaned.txt            # Deduplicated, filtered URL list
├── parameterized_urls.txt      # URLs with query parameters
├── juicy_params.txt            # High-value parameter matches
├── high_priority.txt           # Priority endpoint matches
├── attack_surface.txt          # Combined juicy params
├── forbidden_pages.txt         # 403 responses from httpx
├── interesting_paths.txt       # Interesting path matches
├── error_pages.txt             # 500 responses from httpx
├── domains_clean.txt           # Clean hostnames (no scheme/path)
├── katana_urls.txt             # Katana crawl results (if installed)
├── root_domains.txt            # Base domains for gau --subs
└── js_extracted/               # JS analysis (if not --skip-js)
```

---

## jackpot.sh — Vulnerability Confirmation

Takes a recon directory and confirms exploitable vulnerabilities using pattern matching, parameter injection, and automated probing.

### Usage

```bash
# Basic
./jackpot.sh -f recon_example.com_2026-06-25_08-48-42

# With custom delay and parallelism
./jackpot.sh -f recon_example.com_2026-06-25_08-48-42 -d 0.5 -j 20
```

### What it does

```
Phase 1-2: Preflight
  ├── Check tools (gf, httpx, curl, nuclei, qsreplace)
  └── Validate recon files exist

Phase 3: GF Pattern Scan (13 vuln classes)
  ├── idor, sqli, lfi, rce, xss, ssti
  ├── aws, tokens, cors, firebase, s3-buckets, takeovers, debug
  └── Redirect-param whitelist → redirect_clean.txt

Phase 4: Open Redirect Blast Chain
  ├── Injects 12 payloads via qsreplace
  ├── Single httpx batch (not 12 sequential runs)
  └── Parses Location header for evil.com redirects

Phase 5: 403 Bypass Chain
  ├── 18 path techniques (..;/, %2e%2e%2f, //, etc.)
  ├── 13 header techniques (X-Forwarded-For, X-Original-URL, etc.)
  └── FP filter: skips 0-byte and same-size 200s

Phase 6: Response Analysis (zero HTTP requests)
  └── Mines httpx_results.txt for keywords, errors, tech stack

Phase 6b: 403 Bypass Verification
  ├── Fetches body of each bypass claim
  └── Checks for soft-404/WAF keywords → real vs suspect

Phase 7: SSTI Auto-Verification
  ├── Injects {{7*7777777}} via qsreplace
  ├── Scope filter: skips third-party URLs
  └── Checks for 54444439 in response (not raw payload)

Phase 8: CORS Auto-Verification
  ├── Sends Origin: https://evil.com
  └── Checks for ACAO reflection or wildcard

Phase 9: Nuclei Auto-Verification
  └── Runs nuclei on rce, sqli, ssti, xss, lfi, idor samples
```

### Example terminal output

```
  ╔══════════════════════════════════════════════════════╗
  ║       💰  J A C K P O T . S H  v2.4  💰             ║
  ║      Post-Recon Bug Bounty Vulnerability Scanner     ║
  ╚══════════════════════════════════════════════════════╝

  Target dir : recon_example.com_2026-06-25_08-48-42
  Results    : .../jackpot_results_20260625_101433
  ...

  ┌──────────────────────┐
  │  GF PATTERN SCANNING  │
  └──────────────────────┘
  [P2]  ssti              23 hits  →  gf_results/ssti.txt
  [P2]  sqli              12 hits  →  gf_results/sqli.txt
  [P3]  idor              268 hits →  gf_results/idor.txt
  ...

  ┌───────────────────────────┐
  │  OPEN REDIRECT BLAST CHAIN  │
  └───────────────────────────┘
  ✔  Redirect chain done. 3 confirmed → redirect_confirmed.txt

  ┌──────────────────┐
  │  403 BYPASS CHAIN  │
  └──────────────────┘
  ✔  403 bypass done. 2 confirmed (200) + 1 suspicious

  ┌───────────────────┐
  │  RESPONSE ANALYSIS  │
  └───────────────────┘
  [P1] 500 Internal Server Errors  5 endpoints — high-value injection surface

  ┌──────────────────────────────┐
  │  403 BYPASS VERIFICATION      │
  └──────────────────────────────┘
  [P2] 403 BYPASS VERIFIED (real)  2 bypasses confirmed

  ┌────────────────────────┐
  │  SSTI AUTO-VERIFICATION  │
  └────────────────────────┘
  ✔  SSTI auto-test done. 1 confirmed → ssti_confirmed.txt

  ┌────────────────────────┐
  │  CORS AUTO-VERIFICATION  │
  └────────────────────────┘
  [P2] CORS MISCONFIG  https://api.example.com  (Access-Control-Allow-Origin: *)
```

### Output files

```
jackpot_results_20260625_101433/
├── JACKPOT_SUMMARY.txt              # Full report with action plan
├── jackpot_20260625_101433.log      # Full log with colors
├── redirect_confirmed.txt           # Open redirect findings
├── redirect_bug.txt                 # Detailed redirect debug info
├── 403_bypass_confirmed.txt         # Raw bypass technique matches
├── 403_bypass_suspicious.txt        # 3xx behavior changes
├── 403_bypass_real.txt              # Body-verified bypasses (not soft-404)
├── 403_bypass_suspect_soft404.txt   # Likely WAF/error pages
├── response_analysis.txt            # httpx mining results
├── ssti_confirmed.txt               # SSTI auto-test matches
├── cors_confirmed.txt               # CORS misconfig matches
├── nuclei_confirmed.txt             # Nuclei-verified vulnerabilities
└── gf_results/                      # Per-pattern gf output
    ├── idor.txt, sqli.txt, lfi.txt, rce.txt, xss.txt
    ├── ssti.txt, debug.txt, aws.txt, tokens.txt
    ├── cors.txt, firebase.txt, s3-buckets.txt
    └── takeovers.txt
```

### Summary output sample

```
╔══════════════════════════════════════════════════════╗
║          💰  JACKPOT SCAN COMPLETE  💰               ║
╚══════════════════════════════════════════════════════╝

  Finished : Thu Jun 25 14:29:29 IST 2026
  Target   : recon_example.com_2026-06-25_08-48-42
  Elapsed  : 12 minutes

  ════════════════════════════════════════════════════
   FINDINGS SUMMARY
  ════════════════════════════════════════════════════

  [P1] Open Redirects Confirmed                    3
  [P1] Nuclei Verified Vulns                       2
  [P2] 403 Bypass Verified (real)                  2
  [P2] SSTI Candidates (gf)                        23
  [P2] SQLi Candidates (gf)                        12
  [P3] IDOR Candidates (gf)                        268

  ── CDN / Cloud Hosting Check ───────────────────────
  ✓  No CDN-mirrored domains detected in findings.

  ════════════════════════════════════════════════════
   ACTION PLAN
  ════════════════════════════════════════════════════

  Step 1: Confirm Open Redirects
     → .../redirect_confirmed.txt
     💡 Swap 'evil.com' for your own domain to prove impact

  Step 2: Review 403 Bypass (Phase 6b verified)
     → .../403_bypass_real.txt
     💡 Check what's behind the bypass — admin panels?

  ...
```

--- 

> **Pro tip**: Always run nuclei with `nuclei -ud ~/.nuclei-templates -update-templates` before scanning. Use `-j 20` on fast networks, `-d 1` on WAF-heavy targets.
