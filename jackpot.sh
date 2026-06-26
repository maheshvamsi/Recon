#!/bin/bash
# ════════════════════════════════════════════════════════════════
#   JACKPOT.SH v2.4 — Post-Recon Bug Bounty Vulnerability Scanner
#   Usage: jackpot.sh -f <recon_directory> [-d delay] [-j jobs]
#
#   PHASES:
#     1. Tool Check         → Verify required/optional tools
#     2. File Validation    → Confirm recon directory structure
#     3. GF Pattern Scan    → 13 vuln patterns + auto-install missing
#     4. Redirect Chain     → Confirm open redirects (single batch httpx)
#     5. 403 Bypass         → Recover forbidden pages (parallel curl)
#     6. Response Analysis  → Mine httpx results (zero HTTP reqs)
#     6b.403 Verify         → Soft-404 detection on bypass claims
#     7. SSTI Auto-Test     → Confirm SSTI with {{7*7777777}} probe
#     8. CORS Auto-Test     → Confirm CORS with Origin reflection (curl)
#     9. Nuclei Verify      → Auto-verify gf candidates
#
#   CHANGES v2.4:
#     - Scope filter: extract target domains & skip third-party URLs in
#       SSTI/CORS probes (adobe.com, powerbi.com FPs eliminated)
#     - Phase 6b: 403 bypass verification — fetches body & checks for
#       soft-404 / WAF-block keywords (pattern-based 200 → real bypass)
#     - Resume checkpoints: each phase writes .phase_done_<name> marker;
#       subsequent runs skip completed phases
#     - Throttle helper: consistent $RATE_DELAY before bulk HTTP phases
#     - CDN domain validation in summary: dig +short CNAME on findings
#       to flag CloudFront/Cloudflare/Akamai/Fastly-mirrored hosts
#     - SSTI FP fix: payload changed from {{7*7}} (→"49", common in HTML)
#       to {{7*7777777}} (→"54444439", extremely unlikely naturally);
#       also checks raw payload NOT reflected to exclude echo-back FPs
#     - Color code fix: changed '\\033' → $'\\033' so plain echo outputs
#       real ANSI escapes, eliminating literal \033 text in action plan
# ════════════════════════════════════════════════════════════════

set -uo pipefail

# ─── Scope & checkpoint helpers ────────────────────────────────
# Extracts target base domains from live_subdomains.txt so SSTI/CORS
# probes skip third-party URLs (e.g. adobe.com, powerbi.com).
extract_target_domains() {
  local out="${OUTPUT_DIR}/.in_scope_domains.txt"
  > "$out"
  if [[ -f "${RECON_DIR}/domains_clean.txt" ]]; then
    # Full hostnames (e.g. app.epa.gov)
    sort -u "${RECON_DIR}/domains_clean.txt" >> "$out"
    # Base 2LD domains (e.g. epa.gov from app.epa.gov)
    sed -E 's/^[^.]+\.(.+\..+)$/\1/' "${RECON_DIR}/domains_clean.txt" \
      >> "$out" 2>/dev/null || true
  elif [[ -f "${RECON_DIR}/live_subdomains.txt" ]]; then
    awk -F/ '{print $3}' "${RECON_DIR}/live_subdomains.txt" | sort -u >> "$out"
    sed -E 's/^[^.]+\.(.+\..+)$/\1/' "$out" >> "$out" 2>/dev/null || true
  fi
  sort -u "$out" -o "$out"
}

# Returns 0 if the given URL's host is NOT in the target scope.
url_out_of_scope() {
  [[ ! -f "${OUTPUT_DIR}/.in_scope_domains.txt" ]] && return 1
  local host
  host=$(echo "$1" | awk -F/ '{print $3}' | sed 's/:.*//')
  [[ -z "$host" ]] && return 1
  while IFS= read -r domain; do
    [[ -z "$domain" ]] && continue
    # Case-insensitive suffix match
    if echo "$host" | grep -qiE "(^|\.)${domain}$"; then
      return 1
    fi
  done < "${OUTPUT_DIR}/.in_scope_domains.txt"
  return 0
}

# Filters a URL list to only in-scope hosts.
# Usage: filter_scope <input_file> [output_file]
filter_scope() {
  local input="$1" output="${2:-}"
  [[ -z "$output" ]] && output="${input}.scoped"
  > "$output"
  if [[ ! -f "${OUTPUT_DIR}/.in_scope_domains.txt" || ! -s "${OUTPUT_DIR}/.in_scope_domains.txt" ]]; then
    cp "$input" "$output" 2>/dev/null || true
    return
  fi
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    url_out_of_scope "$url" || echo "$url" >> "$output"
  done < "$input"
}

# ─── Resume / Checkpoint ─────────────────────────────────────
# Creates a marker so subsequent runs skip completed phases.
finish_phase() { touch "${OUTPUT_DIR}/.phase_done_$1"; }
check_phase()  { [[ -f "${OUTPUT_DIR}/.phase_done_$1" ]]; }

# ─── Throttle ────────────────────────────────────────────────
# Ensures consistent pacing before bulk HTTP phases.
throttle() { sleep "$RATE_DELAY"; }

# ─── Colours ────────────────────────────────────────────────────
RED=$'\033[0;31m';    GREEN=$'\033[0;32m';    YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m';   CYAN=$'\033[0;36m';     MAGENTA=$'\033[0;35m'
BOLD=$'\033[1m';      DIM=$'\033[2m';         NC=$'\033[0m'
BGREEN=$'\033[1;32m'; WHITE=$'\033[1;37m'

# ─── Severity colours ─────────────────────────────────────────
P1_COLOR="${RED}${BOLD}"
P2_COLOR="${YELLOW}${BOLD}"
P3_COLOR="${BLUE}${BOLD}"
P4_COLOR="${DIM}"

# ─── Globals ─────────────────────────────────────────────────────
RECON_DIR=""
START_EPOCH=$(date +%s)
START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
LOG_FILE=""
OUTPUT_DIR=""
GF_DIR=""
RATE_DELAY="0.3"
PARALLEL_JOBS=10
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"

# ─── Tool flags ───────────────────────────────────────────────
HAS_GF=false; HAS_QSREPLACE=false; HAS_HTTPX=false
HAS_CURL=false; HAS_NUCLEI=false



# ─── Cleanup trap ────────────────────────────────────────────
# BUG FIX #14 — orphaned temp files were left on Ctrl-C / crash
cleanup() {
  [[ -n "${OUTPUT_DIR:-}" ]] && rm -f \
    "${OUTPUT_DIR}/.redirect_all_results.txt" \
    "${OUTPUT_DIR}/.redirect_all_payloads.txt" \
    "${OUTPUT_DIR}"/.nuclei_*_sample.txt       \
    "${OUTPUT_DIR}/403_temp.txt"               \
    "${OUTPUT_DIR}"/.ssti_*                      \
    "${OUTPUT_DIR}/.in_scope_domains.txt"       \
    "${OUTPUT_DIR}"/.403_verify_*               \
    ${GF_DIR:+${GF_DIR}/*.scoped} "${OUTPUT_DIR}"/*.scoped \
    2>/dev/null || true
  [[ -d "${OUTPUT_DIR:-}/.403_tmp" ]] && rm -rf "${OUTPUT_DIR}/.403_tmp" 2>/dev/null || true
  rm -f "${RECON_DIR}/jackpot_results_"*"/.phase_done_"* 2>/dev/null || true
}
trap cleanup EXIT

# ─── Progress bar ────────────────────────────────────────────
# Used for slow operations (URL gen, redirect payloads, file probe)
# NOT used for fast GF pattern runs — see gf_row() below
progress_bar() {
  local cur=$1 total=$2 label="$3" width=30
  ((total == 0)) && total=1
  local pct=$((cur * 100 / total))
  local fill=$((cur * width / total))
  local empty=$((width - fill))
  printf "\r  ${CYAN}[${NC}"
  printf "%${fill}s" | tr ' ' '╣'
  printf "%${empty}s" | tr ' ' '░'
  printf "${CYAN}]${NC} %3d%% ${DIM}%s${NC}   " "$pct" "${label:0:50}"
  ((cur == total)) && echo ""
}

# ─── Log helpers ─────────────────────────────────────────────
log()     { echo -e "$1" | tee -a "$LOG_FILE"; }
info()    { log "  ${BLUE}*${NC}  $1"; }
success() { log "  ${BGREEN}✔${NC}  $1"; }
warn()    { log "  ${YELLOW}⚠${NC}  $1"; }
error()   { log "  ${RED}✘${NC}  $1"; }

# ─── Section divider ─────────────────────────────────────────
divider() {
  local title="$1"
  local line="${title//?/─}"
  log ""
  log "  ${MAGENTA}${BOLD}┌─${line}─┐${NC}"
  log "  ${MAGENTA}${BOLD}│  ${title}  │${NC}"
  log "  ${MAGENTA}${BOLD}└─${line}─┘${NC}"
}

# ─── Finding box ─────────────────────────────────────────────
finding() {
  local severity="$1" label="$2" detail="$3"
  local sc
  case "$severity" in
    P1) sc="${P1_COLOR}[ P1 CRITICAL ]${NC}" ;;
    P2) sc="${P2_COLOR}[ P2 HIGH     ]${NC}" ;;
    P3) sc="${P3_COLOR}[ P3 MEDIUM   ]${NC}" ;;
    *)  sc="${P4_COLOR}[ P4 INFO     ]${NC}" ;;
  esac
  log "  ${sc}  ${BGREEN}${label}${NC}  ${DIM}${detail}${NC}"
}

# ─── Suggestion ──────────────────────────────────────────────
tip() { log "     ${DIM}💡 ${1}${NC}"; }

# ─── GF result row ───────────────────────────────────────────
# Replaces the per-pattern progress bar with a compact colour table.
# GF runs are near-instant; a progress bar just flickers uselessly.
# BUG FIX #7 — progress_bar was called inside the loop AND again after it
gf_row() {
  local pattern="$1" count="$2"
  local padded; padded=$(printf '%-16s' "$pattern")
  local cnt_fmt; cnt_fmt=$(printf '%6d' "$count")

  if [[ "$count" -eq 0 ]]; then
    log "  ${DIM}  ·  ${padded}  ${cnt_fmt} hits${NC}"
    return
  fi

  local sev="" sc="" flag=""
  case "$pattern" in
    aws|takeovers)            sev="P1"; sc="${P1_COLOR}"; flag="  ${RED}◀ HIGH PRIORITY${NC}" ;;
    cors|tokens|sqli|ssti)   sev="P2"; sc="${P2_COLOR}" ;;
    *)                        sev="P3"; sc="${P3_COLOR}" ;;
  esac

  log "  ${sc}[${sev}]${NC}  ${padded}  ${GREEN}${cnt_fmt} hits${NC}  →  ${DIM}gf_results/${pattern}.txt${NC}${flag}"
}

# ─── Banner ──────────────────────────────────────────────────
print_banner() {
  echo -e "${MAGENTA}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════════╗"
  echo "  ║       💰  J A C K P O T . S H  v2.2  💰             ║"
  echo "  ║      Post-Recon Bug Bounty Vulnerability Scanner     ║"
  echo "  ╚══════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo -e "  ${CYAN}Target dir : ${YELLOW}${RECON_DIR}${NC}"
  echo -e "  ${CYAN}Results    : ${YELLOW}${OUTPUT_DIR}${NC}"
  echo -e "  ${CYAN}Log        : ${YELLOW}${LOG_FILE}${NC}"
  echo -e "  ${CYAN}Start time : ${YELLOW}${START_TIME}${NC}"
  echo -e "  ${CYAN}Delay      : ${YELLOW}${RATE_DELAY}s${NC}    ${CYAN}Parallel   : ${YELLOW}${PARALLEL_JOBS} jobs${NC}"
  echo ""
}

# ─── Usage ───────────────────────────────────────────────────
usage() {
  echo -e "${BOLD}Usage:${NC} $0 -f <recon_directory> [-d delay] [-j parallel_jobs]"
  echo "  -f    Path to recon directory (required)"
  echo "  -d    Delay between requests in seconds (default: 0.3)"
  echo "  -j    Parallel jobs for 403 bypass (default: 10)"
  echo "  -h    Show this help"
  exit 1
}

# ─── Argument Parsing ────────────────────────────────────────
parse_args() {
  while getopts "f:d:j:h" opt; do
    case $opt in
      f) RECON_DIR="$OPTARG" ;;
      d) RATE_DELAY="$OPTARG" ;;
      # BUG FIX #15 — PARALLEL_JOBS had no CLI flag; -j adds it
      j) PARALLEL_JOBS="$OPTARG" ;;
      h) usage ;;
      *) usage ;;
    esac
  done
  [[ -z "$RECON_DIR" ]] && { echo -e "${RED}✘${NC} No recon directory specified."; usage; }
  [[ ! -d "$RECON_DIR" ]] && { echo -e "${RED}✘${NC} Directory '$RECON_DIR' not found."; exit 1; }
  if ! [[ "$PARALLEL_JOBS" =~ ^[1-9][0-9]*$ ]]; then
    echo -e "${RED}✘${NC} -j must be a positive integer."; exit 1
  fi
  RECON_DIR="${RECON_DIR%/}"
  OUTPUT_DIR="${RECON_DIR}/jackpot_results_${TIMESTAMP}"
  GF_DIR="${RECON_DIR}/gf_results"
  LOG_FILE="${OUTPUT_DIR}/jackpot_${TIMESTAMP}.log"
  mkdir -p "$OUTPUT_DIR" "$GF_DIR"
  touch "$LOG_FILE"
}

# ─── Tool Check ──────────────────────────────────────────────
check_tools() {
  divider "TOOL AVAILABILITY CHECK"
  local tool path

  for tool in gf qsreplace httpx curl nuclei; do
    path=$(command -v "$tool" 2>/dev/null || true)
    if [[ -n "$path" ]]; then
      success "$(printf '%-12s' "$tool") ${DIM}${path}${NC}"
      case "$tool" in
        gf)        HAS_GF=true ;;
        qsreplace) HAS_QSREPLACE=true ;;
        httpx)     HAS_HTTPX=true ;;
        curl)      HAS_CURL=true ;;
        nuclei)    HAS_NUCLEI=true ;;
      esac
    else
      case "$tool" in
        gf)        warn "gf not found        — GF pattern scans will be skipped" ;;
        qsreplace) warn "qsreplace not found — redirect chain will be skipped" ;;
        httpx)     warn "httpx not found     — HTTP probing will be skipped" ;;
        curl)      warn "curl not found      — 403 bypass + file checks skipped" ;;
        nuclei)    info "nuclei not found    — auto-verification skipped" ;;
      esac
    fi
  done

  if command -v parallel &>/dev/null; then
    success "$(printf '%-12s' "parallel") ${DIM}$(command -v parallel)${NC}"
  else
    info "parallel not found — using xargs -P instead"
  fi
}

# ─── File Validation ─────────────────────────────────────────
validate_files() {
  divider "VALIDATING RECON DIRECTORY"
  local required_files=("parameterized_urls.txt" "live_subdomains.txt" "urls_cleaned.txt")
  local optional_files=(
    "juicy_params.txt"      "high_priority.txt"   "attack_surface.txt"
    "httpx_results.txt"     "interesting_paths.txt" "forbidden_pages.txt"
    "error_pages.txt"       "katana_urls.txt"     "domains_clean.txt"
  )
  local missing_required=0

  for f in "${required_files[@]}"; do
    if [[ -f "${RECON_DIR}/${f}" ]]; then
      # BUG FIX #6 — numfmt --to=iec was used on a LINE COUNT (not bytes)
      # Line counts are just integers; format with commas for readability
      local count; count=$(wc -l < "${RECON_DIR}/${f}" 2>/dev/null || echo 0)
      success "$(printf 'REQUIRED  %-38s %s lines' "$f" "$(printf '%d' "$count")")"
    else
      error "MISSING REQUIRED: ${f}"
      missing_required=$((missing_required + 1))
    fi
  done

  for f in "${optional_files[@]}"; do
    if [[ -f "${RECON_DIR}/${f}" ]]; then
      local count; count=$(wc -l < "${RECON_DIR}/${f}" 2>/dev/null || echo 0)
      info "$(printf 'OPTIONAL  %-38s %s lines' "$f" "$(printf '%d' "$count")")"
    else
      warn "Optional not found: ${f}"
    fi
  done

  if [[ $missing_required -gt 0 ]]; then
    error "Missing ${missing_required} required file(s). Cannot continue."
    exit 1
  fi
  success "All required files present."
}

# ─── GF: auto-install missing patterns ───────────────────────
install_gf_patterns() {
  # BUG FIX #1 — was hardcoded to /home/isagi/tools/gf-examples
  local GF_EXAMPLES_DIR="${HOME}/tools/gf-examples"
  local GF_EXAMPLES="${GF_EXAMPLES_DIR}/examples"

  # Migrate patterns from old ~/.gf/ location (used by older gf versions)
  # to the new ~/.config/gf/ location (used by gf v2+)
  if [[ -d "${HOME}/.gf" ]] && [[ ! -d "${HOME}/.config/gf" ]]; then
    mkdir -p "${HOME}/.config/gf" 2>/dev/null
    cp -n "${HOME}/.gf"/*.json "${HOME}/.config/gf/" 2>/dev/null || true
    info "Migrated gf patterns from ~/.gf/ to ~/.config/gf/"
  fi

  if [[ ! -d "$GF_EXAMPLES" ]]; then
    if command -v git &>/dev/null; then
      info "Cloning gf-examples repo to ${GF_EXAMPLES_DIR}..."
      mkdir -p "$GF_EXAMPLES_DIR" 2>/dev/null
      git clone --depth 1 https://github.com/tomnomnom/gf-examples \
        "$GF_EXAMPLES_DIR" 2>/dev/null \
        || { warn "Could not clone gf-examples — some patterns may be missing."; return; }
    else
      warn "git not available — cannot auto-install missing gf patterns."
      return
    fi
  fi

  local -a map=(
    "aws-keys.json:aws"          "json-sec.json:tokens"   "cors.json:cors"
    "s3-buckets.json:s3-buckets" "takeovers.json:takeovers"
    "debug-pages.json:debug"     "firebase.json:firebase"
  )
  for entry in "${map[@]}"; do
    local src="${entry%%:*}" dst="${entry##*:}"
    if ! gf -list 2>&1 | grep -qxi "$dst"; then
      if [[ -f "${GF_EXAMPLES}/${src}" ]]; then
        mkdir -p "${HOME}/.config/gf" 2>/dev/null
        cp "${GF_EXAMPLES}/${src}" "${HOME}/.config/gf/${dst}.json" 2>/dev/null
        success "Installed gf pattern: ${dst}"
      fi
    fi
  done
}

# ─── PHASE 3: GF Pattern Scanning ────────────────────────────
run_gf_scans() {
  check_phase "03_gf" && { info "Phase 3 already completed — skipping."; return; }
  divider "GF PATTERN SCANNING"
  if [[ "$HAS_GF" == "false" ]]; then
    warn "gf not installed — skipping."
    tip "Install: go install github.com/tomnomnom/gf@latest"
    finish_phase "03_gf"; return
  fi

  install_gf_patterns

  local PARAM_FILE="${RECON_DIR}/parameterized_urls.txt"
  local CLEAN_FILE="${RECON_DIR}/urls_cleaned.txt"

  # BUG FIX #17 — raw parameterized_urls.txt has tons of duplicates and
  # static asset URLs that GF can never exploit. Dedup + filter once here
  # instead of letting gf churn through noise for every pattern.
  local PARAM_DEDUP="${GF_DIR}/.param_dedup.txt"
  info "Deduplicating & filtering parameterized URLs..."
  sort -u "$PARAM_FILE" \
    | grep -vE '\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|map|eot)(\?|$)' \
    > "$PARAM_DEDUP" 2>/dev/null || true
  local orig_count filtered_count
  orig_count=$(wc -l < "$PARAM_FILE" 2>/dev/null || echo 0)
  filtered_count=$(wc -l < "$PARAM_DEDUP" 2>/dev/null || echo 0)
  info "URLs: ${orig_count} raw → ${filtered_count} after dedup + static-asset filter"

  local -a patterns=("idor" "sqli" "lfi" "rce" "xss" "ssti" "debug" "aws" "tokens" "cors" "firebase" "s3-buckets" "takeovers")

  # Print table header (replaces the per-pattern flickering progress bar)
  log ""
  log "  ${WHITE}${BOLD}  SEV   PATTERN            HITS   OUTPUT${NC}"
  log "  ${DIM}  ─────────────────────────────────────────────────────────${NC}"

  for pattern in "${patterns[@]}"; do
    local input="$PARAM_DEDUP"
    case "$pattern" in aws|tokens|cors|takeovers) input="$CLEAN_FILE";; esac

    # BUG FIX #11 — skip silently if pattern is not installed
    if ! gf -list 2>&1 | grep -qxi "$pattern"; then
      log "  ${DIM}  ·  $(printf '%-16s' "$pattern")  (pattern not installed — run install step)${NC}"
      touch "${GF_DIR}/${pattern}.txt"
      continue
    fi

    gf "$pattern" "$input" > "${GF_DIR}/${pattern}.txt" 2>/dev/null || true
    local count; count=$(wc -l < "${GF_DIR}/${pattern}.txt" 2>/dev/null || echo 0)
    gf_row "$pattern" "$count"

    # Escalate P1 patterns to finding() so they appear in the log summary block
    if [[ "${count:-0}" -gt 0 ]] && [[ "$pattern" == "aws" || "$pattern" == "takeovers" ]]; then
      finding "P1" "gf ${pattern}" "${count} candidates → gf_results/${pattern}.txt"
    fi
  done

  log "  ${DIM}  ─────────────────────────────────────────────────────────${NC}"
  # BUG FIX #7 — removed the redundant progress_bar 100% call that used
  # to appear here; the loop's final iteration already reached 100%

  # ── Redirect filtering ───────────────────────────────────
  info "Filtering redirect parameters..."
  gf redirect "$PARAM_DEDUP" > "${GF_DIR}/redirect_raw.txt" 2>/dev/null || true
  local redir_params="redirect|url|return|dest|next|goto|forward|redir|out|view|dir|show|file|document|folder|root|path|main|page|location|reference|site|target|to|uri"
  grep -iE "[?&](${redir_params})=" "${GF_DIR}/redirect_raw.txt" \
    > "${GF_DIR}/redirect_clean.txt" 2>/dev/null || true
  local raw_r; raw_r=$(wc -l < "${GF_DIR}/redirect_raw.txt"   2>/dev/null || echo 0)
  local cln_r; cln_r=$(wc -l < "${GF_DIR}/redirect_clean.txt" 2>/dev/null || echo 0)
  gf_row "redirect (filtered)" "$cln_r"
  info "redirect: ${raw_r} raw → ${cln_r} after param-name whitelist filter"

  rm -f "$PARAM_DEDUP"
  finish_phase "03_gf"
  success "GF scanning complete."
}

# ─── PHASE 4: Open Redirect Blast Chain ──────────────────────
run_redirect_chain() {
  check_phase "04_redirect" && { info "Phase 4 already completed — skipping."; return; }
  divider "OPEN REDIRECT BLAST CHAIN"
  if [[ "$HAS_QSREPLACE" == "false" || "$HAS_HTTPX" == "false" ]]; then
    warn "qsreplace or httpx missing — skipping."
    finish_phase "04_redirect"; return
  fi
  local INPUT="${GF_DIR}/redirect_clean.txt"
  if [[ ! -f "$INPUT" || ! -s "$INPUT" ]]; then
    warn "No redirect candidates — skipping."
    return
  fi

  local CONFIRMED="${OUTPUT_DIR}/redirect_confirmed.txt"
  local BUG_FILE="${OUTPUT_DIR}/redirect_bug.txt"
  local ALL_RESULTS="${OUTPUT_DIR}/.redirect_all_results.txt"
  > "$CONFIRMED" > "$BUG_FILE" > "$ALL_RESULTS"

  local -a payloads=(
    "//evil.com%2f%2f"             "//evil.com%252f%252f"
    "https:evil.com"               "https:\\\\evil.com"
    "//evil.com%2f%2f@google.com"  "//evil.com%2f%2f.google.com"
    "/\\/\\/evil.com/"             "%2F%2Fevil.com"
    "%252F%252Fevil.com"           "//evil.com%00"
    "//evil.com%0a"                "//evil.com/?google.com"
  )

  local url_count; url_count=$(wc -l < "$INPUT")
  info "Testing ${url_count} redirect URLs × ${#payloads[@]} payloads (single httpx batch)"
  tip "Replace 'evil.com' with your Burp Collaborator / canary domain"

  local ALL_PAYLOADS="${OUTPUT_DIR}/.redirect_all_payloads.txt"
  > "$ALL_PAYLOADS"

  for payload in "${payloads[@]}"; do
    < "$INPUT" xargs -P "$PARALLEL_JOBS" -I{} bash -c \
      'u=$(printf "%s" "$1" | qsreplace "'"$payload"'" 2>/dev/null)
       [ -n "$u" ] && [ "$u" != "$1" ] && printf "%s\n" "$u"' \
      _ {} >> "$ALL_PAYLOADS" 2>/dev/null
  done

  local pcount; pcount=$(wc -l < "$ALL_PAYLOADS" 2>/dev/null || echo 0)
  if [[ "${pcount:-0}" -eq 0 ]]; then
    info "No payload URLs generated — skipping."
    rm -f "$ALL_PAYLOADS"
    return
  fi

  info "Probing ${pcount} generated URLs with httpx..."
  throttle
  httpx -silent -status-code -location -timeout 5 -no-color -t 50 \
    -l "$ALL_PAYLOADS" >> "$ALL_RESULTS" 2>/dev/null || true
  rm -f "$ALL_PAYLOADS"

  # BUG FIX #8 — old message said "Parsing ${total} batch results" where
  # $total = URL count, not result count. Now explicitly labels each.
  local result_count; result_count=$(wc -l < "$ALL_RESULTS" 2>/dev/null || echo 0)
  info "Parsing ${result_count} httpx results (from ${url_count} URLs)..."

  local count=0
  while IFS= read -r result; do
    [[ -z "$result" ]] && continue
    local location loc_host
    location=$(echo "$result" | awk -F'\\[|\\]' '{print $4}' 2>/dev/null)

    # BUG FIX #10 — protocol-relative Location (//evil.com) was not extracted
    # by the scheme://host regex and therefore never matched evil.com
    if [[ "$location" == //* ]]; then
      loc_host=$(echo "$location" | sed -E 's|^//([^/?#]+).*|\1|')
    else
      loc_host=$(echo "$location" | sed -E 's|^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#]+).*|\1|')
    fi

    if echo "$result" | grep -qE "\[(301|302|303|307|308)\]" \
    && echo "$loc_host" | grep -qiE "(^|\.)evil\.com$"; then
      echo "$result" >> "$CONFIRMED"
      { echo "RESULT : $result"; echo "---"; } >> "$BUG_FILE"
      finding "P1" "OPEN REDIRECT" "$(echo "$result" | awk '{print $1}')"
      count=$((count + 1))
    fi
  done < "$ALL_RESULTS"
  rm -f "$ALL_RESULTS"

  if [[ "$count" -eq 0 ]]; then
    info "No open redirects confirmed (host-only check applied)"
    tip "Try substituting 'evil.com' with your own callback domain"
  fi
  finish_phase "04_redirect"
  success "Redirect chain done. ${count} confirmed → ${CONFIRMED}"
}

# ─── Helper: scan a single 403 URL (parallel worker) ─────────
# Exported for use in xargs subshells.
scan_url_403() {
  local url="$1" out_dir="$2" rate_delay="$3" user_agent="$4"
  [[ -z "$url" ]] && return

  local HOST_FILE="${out_dir}/.403_$(printf '%s' "$url" | md5sum | cut -c1-12).txt"

  # ── Baseline ────────────────────────────────────────────
  local base_code base_size
  read -r base_code base_size < <(
    curl -s -k --path-as-is -o /dev/null \
      -w "%{http_code} %{size_download}" \
      -A "$user_agent" --max-time 10 "$url" 2>/dev/null \
    || echo "000 0"
  )
  # BUG FIX #3 — rate_delay was received as $3 but sleep was never called,
  # so the -d flag had zero effect on actual request pacing
  sleep "$rate_delay"

  # ── Path-based bypass techniques ────────────────────────
  local -a path_bypasses=(
    "/..;/" "/%2e%2e%2f" "/?%2e%2e%2f" "//"
    "/%2e%2e" "/..%2f" "/%2e%2e%2f..%2f" "/..;/..;/"
    "/...%2f%2f" "/%2e%2e//" "/../" "/;/" "/.;/"
    "?redirect=..%2f" "%2e%2e%2f" "..%252f" "..%c0%af" "..%c1%9c"
  )
  local -a header_bypasses=(
    "X-Forwarded-For: 127.0.0.1"
    "X-Forwarded-For: 127.0.0.1, 127.0.0.2"
    "X-Real-IP: 127.0.0.1"
    "X-Custom-IP-Authorization: 127.0.0.1"
    "X-Forwarded-Host: localhost"
    "X-Original-URL: /" "X-Rewrite-URL: /" "X-Override-URL: /"
    "Referer: https://localhost/"
    "Client-IP: 127.0.0.1" "True-Client-IP: 127.0.0.1"
    "Cluster-Client-IP: 127.0.0.1" "X-ProxyUser-Ip: 127.0.0.1"
  )

  local -A seen_path
  for bypass in "${path_bypasses[@]}"; do
    local test_url
    test_url=$(echo "$url" | sed "s|://[^/]*/|&${bypass#/}|")
    [[ -n "${seen_path[$test_url]:-}" ]] && continue
    seen_path[$test_url]=1

    local http_code size
    read -r http_code size < <(
      curl -s -k --path-as-is -o /dev/null \
        -w "%{http_code} %{size_download}" \
        -A "$user_agent" --max-time 10 "$test_url" 2>/dev/null \
      || echo "000 0"
    )

    # BUG FIX #13 — old code flagged ANY 200 as BYPASS_200, including
    # WAF "blocked" pages that return 200 with an empty or identical body.
    # Now we require: size > 100 bytes AND different from the baseline.
    if [[ "$http_code" == "200" && "${size:-0}" -gt 100 && "$size" != "$base_size" ]]; then
      echo "[PATH|BYPASS_200|size:${size}vs${base_size}] ${test_url}" >> "$HOST_FILE"
    elif [[ "$http_code" =~ ^(301|302|303|307|308)$ && "$size" != "$base_size" ]]; then
      echo "[PATH|SUSPICIOUS|HTTP:${http_code}|size:${size}vs${base_size}] ${test_url}" >> "$HOST_FILE"
    elif [[ "$http_code" =~ ^(20[1-9]|206)$ ]]; then
      echo "[PATH|PARTIAL|HTTP:${http_code}|size:${size}] ${test_url}" >> "$HOST_FILE"
    fi
  done

  # ── Header-based bypass techniques ──────────────────────
  # BUG FIX #2 — 'seen_header' was declared as local -A but never used;
  # only 'seen_header_result' was used. Removed the dead declaration.
  local -A seen_header_result
  for header in "${header_bypasses[@]}"; do
    local http_code size
    read -r http_code size < <(
      curl -s -k --path-as-is -o /dev/null \
        -w "%{http_code} %{size_download}" \
        -A "$user_agent" --max-time 10 -H "$header" "$url" 2>/dev/null \
      || echo "000 0"
    )

    local result_key="${http_code}:${size}"
    [[ -n "${seen_header_result[$result_key]:-}" ]] && continue
    seen_header_result[$result_key]=1

    # Same FP filter as path bypasses: require non-trivial, different-size 200
    if [[ "$http_code" == "200" && "${size:-0}" -gt 100 && "$size" != "$base_size" ]]; then
      echo "[HEADER|BYPASS_200|header:'${header}'] ${url}" >> "$HOST_FILE"
    elif [[ "$http_code" =~ ^(301|302|303|307|308)$ && "$size" != "$base_size" ]]; then
      echo "[HEADER|SUSPICIOUS|HTTP:${http_code}|size:${size}|header:'${header}'] ${url}" >> "$HOST_FILE"
    fi
  done
}
export -f scan_url_403

# ─── PHASE 5: 403 Bypass Chain ───────────────────────────────
run_403_bypass() {
  check_phase "05_403" && { info "Phase 5 already completed — skipping."; return; }
  divider "403 BYPASS CHAIN"
  if [[ "$HAS_CURL" == "false" ]]; then
    warn "curl missing — skipping."
    finish_phase "05_403"; return
  fi

  local TEMP_403="${OUTPUT_DIR}/403_temp.txt"
  > "$TEMP_403"
  [[ -f "${RECON_DIR}/httpx_results.txt" ]] && \
    grep "\[403\]" "${RECON_DIR}/httpx_results.txt" | awk '{print $1}' >> "$TEMP_403" 2>/dev/null || true
  [[ -f "${RECON_DIR}/forbidden_pages.txt" ]] && \
    awk '{print $1}' "${RECON_DIR}/forbidden_pages.txt" >> "$TEMP_403" 2>/dev/null || true
  sort -u "$TEMP_403" -o "$TEMP_403"

  local total; total=$(wc -l < "$TEMP_403" 2>/dev/null || echo 0)
  if [[ "$total" -eq 0 ]]; then
    warn "No 403 URLs found — skipping."
    return
  fi

  local CONFIRMED="${OUTPUT_DIR}/403_bypass_confirmed.txt"
  local SUSPICIOUS="${OUTPUT_DIR}/403_bypass_suspicious.txt"
  local BYPASS_TMP="${OUTPUT_DIR}/.403_tmp"
  mkdir -p "$BYPASS_TMP"
  > "$CONFIRMED" > "$SUSPICIOUS"

  info "Testing ${total} forbidden URLs (parallel=${PARALLEL_JOBS})..."
  tip "Each URL: 18 path techniques + 13 header techniques"
  tip "FP reduction: 0-byte and same-size-as-baseline 200s are skipped"

  # BUG FIX #9 — same xargs URL-injection fix as redirect chain;
  # URL is now passed as $1 to the bash -c subshell, not embedded inline
  < "$TEMP_403" xargs -P "$PARALLEL_JOBS" -I{} bash -c \
    'scan_url_403 "$1" "'"$BYPASS_TMP"'" "'"$RATE_DELAY"'" "'"$USER_AGENT"'"' \
    _ {} 2>/dev/null

  local confirmed_count=0 suspicious_count=0
  if [[ -d "$BYPASS_TMP" ]]; then
    for f in "$BYPASS_TMP"/.403_*.txt; do
      [[ ! -f "$f" ]] && continue
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if echo "$line" | grep -q "BYPASS_200"; then
          echo "$line" >> "$CONFIRMED"
        else
          echo "$line" >> "$SUSPICIOUS"
        fi
      done < <(sort -u "$f")
      rm -f "$f"
    done
    sort -u "$CONFIRMED" -o "$CONFIRMED"
    sort -u "$SUSPICIOUS" -o "$SUSPICIOUS"
    confirmed_count=$(wc -l < "$CONFIRMED" 2>/dev/null || echo 0)
    suspicious_count=$(wc -l < "$SUSPICIOUS" 2>/dev/null || echo 0)
    rmdir "$BYPASS_TMP" 2>/dev/null || true
    # BUG FIX #4 — removed bypass_count = confirmed + suspicious; it was
    # assigned here but never read anywhere after this point
  fi

  [[ "${confirmed_count:-0}" -gt 0 ]] && {
    finding "P2" "403 BYPASS CONFIRMED (200)" "${confirmed_count} endpoints became accessible"
    tip "Verify in Burp Repeater — confirm the response body isn't a soft-404"
  }
  [[ "${suspicious_count:-0}" -gt 0 ]] && {
    finding "P2" "403 BYPASS SUSPICIOUS (3xx)" "${suspicious_count} changed behavior vs baseline"
    tip "Different size from baseline → possible WAF interaction, investigate"
  }
  finish_phase "05_403"
  success "403 bypass done. ${confirmed_count} confirmed (200) + ${suspicious_count} suspicious → ${CONFIRMED}"
}

# ─── PHASE 6: Response Analysis ──────────────────────────────
run_response_analysis() {
  check_phase "06_response" && { info "Phase 6 already completed — skipping."; return; }
  divider "RESPONSE ANALYSIS"
  local HTTPX="${RECON_DIR}/httpx_results.txt"
  if [[ ! -f "$HTTPX" || ! -s "$HTTPX" ]]; then
    warn "httpx_results.txt not found — skipping."
    finish_phase "06_response"; return
  fi
  local OUT="${OUTPUT_DIR}/response_analysis.txt"
  info "Mining httpx_results.txt (zero additional HTTP requests)..."

  {
    echo "════════════════════════════════════════════════════"
    echo "  RESPONSE ANALYSIS REPORT — $(date)"
    echo "  Source: ${HTTPX}"
    echo "════════════════════════════════════════════════════"
    echo ""
    echo "── 200 OK with Sensitive Keywords ──────────────────"
    grep "\[200\]" "$HTTPX" \
      | grep -iE "(admin|dashboard|config|secret|token|api[_-]?key|password|credential|cred|intern|staging|dev|test|backup|db|database|debug|env|\.git|swagger|graphql|console|phpmyadmin|manager|portal|setup|install|\.aws|\.ssh|logs?)" \
      || echo "(none found)"
    echo ""
    echo "── Interesting 301/302 Redirects ────────────────────"
    grep -E "\[30[12]\]" "$HTTPX" || echo "(none found)"
    echo ""
    echo "── 500 Internal Server Errors ───────────────────────"
    grep "\[500\]" "$HTTPX" || echo "(none found)"
    grep -q '\[500\]' "$HTTPX" 2>/dev/null \
      && echo "  → 500s are prime SQLi / SSTI / RCE targets!"
    echo ""
    echo "── Juicy Titles (admin/login/panel) ─────────────────"
    grep -iE "\[(Admin|Login|Dashboard|Console|Panel|Portal|Manager|CMS|Control|Setup|Install|Config|API|Swagger|GraphQL|Kibana|Grafana|Jenkins|PHPMyAdmin|cPanel|Webmin|Tomcat)\]" "$HTTPX" \
      || echo "(none found)"
    echo ""
    echo "── Technology Stack Fingerprints ────────────────────"
    grep -iE "(PHP|ASP\.NET|JSP|Laravel|Django|Rails|Spring|Express|WordPress|Joomla|Drupal|Struts|ColdFusion|Tomcat|nginx|Apache|IIS)" "$HTTPX" \
      | head -50 || echo "(none found)"
    echo ""
    echo "── Non-Standard Ports ───────────────────────────────"
    grep -oP 'https?://[^/\s]+:\d{4,5}' "$HTTPX" | sort -u || echo "(none found)"
  } | tee "$OUT" | tee -a "$LOG_FILE"

  local keyword_count; keyword_count=$(grep "\[200\]" "$HTTPX" | grep -ciE "(admin|dashboard|config|secret|token|api[_-]?key|password|credential|cred|intern|staging|dev|test|backup|db|database|debug|env|\.git|swagger|graphql|console|phpmyadmin|manager|portal|setup|install|\.aws|\.ssh|logs?)" 2>/dev/null | tr -d '\n\r' || echo 0)
  local error_count;   error_count=$(grep  -c "\[500\]" "$HTTPX" 2>/dev/null | tr -d '\n\r' || echo 0)
  local juicy_count;   juicy_count=$(grep  -cE "\[(Admin|Login|Dashboard|Console|Panel|Portal|Manager|CMS)\]" "$HTTPX" 2>/dev/null | tr -d '\n\r' || echo 0)

  [[ "${keyword_count:-0}" -gt 0 ]] && {
    finding "P3" "200 responses with sensitive keywords" "${keyword_count} URLs"
    tip "Check for login panels, config pages, debug endpoints"
  }
  [[ "${error_count:-0}" -gt 0 ]] && {
    finding "P1" "500 Internal Server Errors" "${error_count} endpoints — high-value injection surface"
    tip "Test immediately with SQLi / SSTI / RCE payloads"
  }
  [[ "${juicy_count:-0}" -gt 0 ]] && {
    finding "P2" "Juicy admin/login/dashboard titles" "${juicy_count} pages"
    tip "Try default creds, 403 bypass, IDOR on these endpoints"
  }
  finish_phase "06_response"
  success "Response analysis done → ${OUT}"
}

# ─── PHASE 6b: 403 Bypass Verification (soft-404 detection) ──
run_403_bypass_verify() {
  check_phase "06b_403_verify" && { info "Phase 6b already completed — skipping."; return; }
  divider "403 BYPASS VERIFICATION (soft-404 detection)"
  if [[ "$HAS_CURL" == "false" ]]; then
    warn "curl missing — skipping."
    finish_phase "06b_403_verify"; return
  fi

  local CONFIRMED="${OUTPUT_DIR}/403_bypass_confirmed.txt"
  if [[ ! -f "$CONFIRMED" || ! -s "$CONFIRMED" ]]; then
    info "No 403 bypasses to verify — skipping."
    finish_phase "06b_403_verify"; return
  fi

  local total; total=$(wc -l < "$CONFIRMED")
  info "Verifying ${total} bypass claims (checking for soft-404 / WAF page)..."
  local REAL="${OUTPUT_DIR}/403_bypass_real.txt"
  local SUSPECT="${OUTPUT_DIR}/403_bypass_suspect_soft404.txt"
  > "$REAL" > "$SUSPECT"

  # Common soft-404 / WAF-block / error-page indicators in <title> or <body>
  local soft404_re="(404\s*(not\s*found|error)?|not\s*found|page\s*not\s*found|access\s*denied|forbidden|unauthorized|error\s*404|file\s*not\s*found|the\s*page\s*you\s*are\s*looking\s*for|cannot\s*be\s*found|oops|something\s*went\s*wrong|blocked|waf|access\s*control)"

  local verified=0 suspect=0
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local url
    url=$(echo "$line" | grep -oP 'https?://\S+' | head -1)
    [[ -z "$url" ]] && continue

    # Fetch body (first 5 KB) and check for soft-404 patterns
    local body
    body=$(curl -s -k --path-as-is --max-time 8 \
      -A "$USER_AGENT" \
      --max-filesize 5120 "$url" 2>/dev/null || true)
    throttle

    if echo "$body" | grep -qiE "$soft404_re"; then
      echo "[SUSPECT_SOFT404] ${line}" >> "$SUSPECT"
      suspect=$((suspect + 1))
    else
      echo "${line}" >> "$REAL"
      verified=$((verified + 1))
    fi
  done < "$CONFIRMED"

  sort -u "$REAL" -o "$REAL"
  sort -u "$SUSPECT" -o "$SUSPECT"

  if [[ "${verified:-0}" -gt 0 ]]; then
    finding "P2" "403 BYPASS VERIFIED (real)" "${verified} bypasses confirmed — not a soft-404 → ${REAL}"
  fi
  if [[ "${suspect:-0}" -gt 0 ]]; then
    finding "P3" "403 BYPASS SUSPECTED SOFT-404" "${suspect} may be WAF/error pages → ${SUSPECT}"
  fi
  finish_phase "06b_403_verify"
  success "403 bypass verification done. ${verified} real → ${REAL}, ${suspect} suspect soft-404 → ${SUSPECT}"
}

# ─── PHASE 7: SSTI Auto-Verification ─────────────────────────
run_ssti_auto_test() {
  check_phase "07_ssti" && { info "Phase 7 already completed — skipping."; return; }
  divider "SSTI AUTO-VERIFICATION"
  if [[ "$HAS_CURL" == "false" || "$HAS_QSREPLACE" == "false" ]]; then
    warn "curl or qsreplace missing — skipping."
    finish_phase "07_ssti"; return
  fi

  local INPUT="${GF_DIR}/ssti.txt"
  if [[ ! -f "$INPUT" || ! -s "$INPUT" ]]; then
    info "No SSTI candidates — skipping."
    return
  fi

  local PAYLOAD="{{7*7777777}}"
  local INDICATOR="54444439"

  local OUT="${OUTPUT_DIR}/ssti_confirmed.txt"
  local SSTI_TMP="${OUTPUT_DIR}/.ssti_payloads.txt"
  > "$OUT" > "$SSTI_TMP"

  local total; total=$(wc -l < "$INPUT")
  local MAX_SAMPLE=100
  if [[ "$total" -gt "$MAX_SAMPLE" ]]; then
    if command -v shuf &>/dev/null; then
      shuf -n "$MAX_SAMPLE" "$INPUT" > "${SSTI_TMP}.sample"
    else
      sort -R "$INPUT" | head -n "$MAX_SAMPLE" > "${SSTI_TMP}.sample"
    fi
    info "SSTI: sampling ${MAX_SAMPLE}/${total} URLs (payload: ${PAYLOAD})"
    local input="${SSTI_TMP}.sample"
  else
    info "SSTI: testing ${total} URLs (payload: ${PAYLOAD})"
    local input="$INPUT"
  fi

  # Scope filter: skip third-party URLs
  local SCOPED="${input}.scoped"
  filter_scope "$input" "$SCOPED"
  input="$SCOPED"

  < "$input" xargs -P "$PARALLEL_JOBS" -I{} bash -c \
    'u=$(printf "%s" "$1" | qsreplace "'"$PAYLOAD"'" 2>/dev/null)
     [ -n "$u" ] && [ "$u" != "$1" ] && printf "%s\n" "$u"' \
    _ {} > "$SSTI_TMP" 2>/dev/null

  local pcount; pcount=$(wc -l < "$SSTI_TMP" 2>/dev/null || echo 0)
  if [[ "${pcount:-0}" -eq 0 ]]; then
    rm -f "$SSTI_TMP" "${SSTI_TMP}.sample"
    info "No SSTI test URLs generated."
    success "SSTI auto-test done. 0 confirmed → ${OUT}"
    return
  fi

  info "Probing ${pcount} URLs with curl (parallel=${PARALLEL_JOBS})..."
  throttle
  local CONFIRMED_TMP="${OUTPUT_DIR}/.ssti_confirmed_tmp.txt"
  > "$CONFIRMED_TMP"

  < "$SSTI_TMP" xargs -P "$PARALLEL_JOBS" -I{} bash -c \
    'body=$(curl -s -k --path-as-is --max-time 8 \
       -A "'"$USER_AGENT"'" "{}" 2>/dev/null)
     echo "$body" | grep -qF "'"$INDICATOR"'" && \
       echo "$body" | grep -qvF "'"$PAYLOAD"'" && echo "{}"' \
    2>/dev/null >> "$CONFIRMED_TMP"

  if [[ -s "$CONFIRMED_TMP" ]]; then
    sort -u "$CONFIRMED_TMP" > "$OUT"
    while IFS= read -r url; do
      finding "P1" "SSTI CONFIRMED" "${url}  (payload: ${PAYLOAD})"
    done < "$OUT"
    tip "Confirm by injecting: cat /etc/passwd or id"
  else
    info "No SSTI confirmed."
  fi

  rm -f "$SSTI_TMP" "${SSTI_TMP}.sample" "${SSTI_TMP}.sample.scoped" "${CONFIRMED_TMP}"
  rm -f "${GF_DIR}/ssti.txt.scoped" 2>/dev/null || true
  finish_phase "07_ssti"
  local found; found=$(wc -l < "$OUT" 2>/dev/null || echo 0)
  success "SSTI auto-test done. ${found} confirmed → ${OUT}"
}

# ─── PHASE 8: CORS Auto-Verification ─────────────────────────
run_cors_auto_test() {
  check_phase "08_cors" && { info "Phase 8 already completed — skipping."; return; }
  divider "CORS AUTO-VERIFICATION"
  if [[ "$HAS_CURL" == "false" ]]; then
    warn "curl missing — skipping."
    finish_phase "08_cors"; return
  fi

  local INPUT="${GF_DIR}/cors.txt"
  if [[ ! -f "$INPUT" || ! -s "$INPUT" ]]; then
    info "No CORS candidates — skipping."
    finish_phase "08_cors"; return
  fi

  local OUT="${OUTPUT_DIR}/cors_confirmed.txt"
  > "$OUT"

  # Scope filter: skip third-party URLs
  local SCOPED="${INPUT}.scoped"
  filter_scope "$INPUT" "$SCOPED"
  local input_scoped="$SCOPED"

  local total; total=$(wc -l < "$input_scoped")
  info "Testing ${total} CORS candidates with Origin: https://evil.com..."

  local EVIL_ORIGIN="https://evil.com"
  local count=0
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    local acao
    acao=$(curl -s -k --path-as-is --max-time 8 \
      -H "Origin: ${EVIL_ORIGIN}" \
      -A "$USER_AGENT" \
      -D - "$url" 2>/dev/null | grep -i "access-control-allow-origin" | tr -d '\n\r' || true)
    if echo "$acao" | grep -qiF "$EVIL_ORIGIN" || echo "$acao" | grep -qiF "*"; then
      echo "[CORS|ORIGIN_REFLECTED] ${url}  →  ${acao}" >> "$OUT"
      finding "P2" "CORS MISCONFIG" "${url}  (${acao})"
      count=$((count + 1))
    fi
    sleep "$RATE_DELAY"
  done < "$input_scoped"

  rm -f "$SCOPED" "${GF_DIR}/cors.txt.scoped" 2>/dev/null || true

  if [[ "${count:-0}" -gt 0 ]]; then
    tip "Confirm with: curl -H 'Origin: https://evil.com' -I <url>"
  else
    info "No CORS misconfigurations confirmed."
  fi
  finish_phase "08_cors"
  success "CORS auto-test done. ${count} confirmed → ${OUT}"
}

# ─── PHASE 9: Nuclei Auto-Verification ───────────────────────
run_nuclei_verification() {
  check_phase "09_nuclei" && { info "Phase 9 already completed — skipping."; return; }
  divider "NUCLEI AUTO-VERIFICATION"
  if [[ "$HAS_NUCLEI" == "false" ]]; then
    info "nuclei not installed — skipping."
    tip "Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    finish_phase "09_nuclei"; return
  fi

  local OUT="${OUTPUT_DIR}/nuclei_confirmed.txt"
  > "$OUT"

  local -A tags
  tags[rce]="rce,cve,command-injection"
  tags[sqli]="sqli,sql-injection"
  tags[ssti]="ssti"
  tags[xss]="xss"
  tags[lfi]="lfi,path-traversal"
  tags[idor]="idor"

  local MAX_SAMPLE=500 TIMEOUT_PER=180 NUCLEI_MAX=3
  local -a nuclei_pids=()

  for pattern in "${!tags[@]}"; do
    local input="${GF_DIR}/${pattern}.txt"
    [[ ! -f "$input" || ! -s "$input" ]] && continue

    local sample="${OUTPUT_DIR}/.nuclei_${pattern}_sample.txt"
    local total; total=$(wc -l < "$input")
    if [[ "$total" -gt "$MAX_SAMPLE" ]]; then
      if command -v shuf &>/dev/null; then
        shuf -n "$MAX_SAMPLE" "$input" > "$sample" 2>/dev/null
      else
        sort -R "$input" | head -n "$MAX_SAMPLE" > "$sample" 2>/dev/null
      fi
      info "nuclei ${pattern}: sampling ${MAX_SAMPLE}/${total} URLs (tags: ${tags[$pattern]})"
    else
      cp "$input" "$sample"
      info "nuclei ${pattern}: ${total} URLs (tags: ${tags[$pattern]})"
    fi

    while (( ${#nuclei_pids[@]} >= NUCLEI_MAX )); do
      for pid in "${!nuclei_pids[@]}"; do
        kill -0 "${nuclei_pids[$pid]}" 2>/dev/null || unset 'nuclei_pids[$pid]'
      done
      sleep 1
    done

    # BUG FIX #18 — no -severity flag meant info/unknown templates ran too;
    # restrict to medium/high/critical to cut false positives significantly
    timeout "$TIMEOUT_PER" nuclei \
      -silent -timeout 5 -c 25 -no-color \
      -severity medium,high,critical \
      -l "$sample" -tags "${tags[$pattern]}" 2>/dev/null \
      | awk -v pat="$pattern" '!/\[(info|unknown)\]/ {print "["pat"] " $0}' >> "$OUT" &
    nuclei_pids+=($!)
  done
  wait 2>/dev/null || true
  rm -f "${OUTPUT_DIR}"/.nuclei_*_sample.txt

  # BUG FIX #5 — 'local var=$(cmd)' masks cmd's exit code;
  # split into declaration + assignment so pipefail can propagate correctly
  local total_found
  total_found=$(wc -l < "$OUT" 2>/dev/null || echo 0)

  if [[ "${total_found:-0}" -gt 0 ]]; then
    finding "P1" "NUCLEI CONFIRMED" "${total_found} verified vulnerabilities → nuclei_confirmed.txt"
    tip "Auto-confirmed — write reports immediately."
  else
    info "Nuclei found no verified vulnerabilities."
    tip "GF candidates may be FPs — manual testing still recommended."
  fi
  finish_phase "09_nuclei"
  success "Nuclei verification done → ${OUT}"
}

# ─── Summary & Prioritisation ────────────────────────────────
print_summary() {
  divider "JACKPOT SCAN COMPLETE"

  local redirect_count=0 bypass_200=0 bypass_3xx=0
  local xss_c=0 sqli_c=0 lfi_c=0 rce_c=0 ssti_c=0 idor_c=0 debug_c=0
  local aws_c=0 tokens_c=0 cors_c=0 firebase_c=0 s3_c=0 takeover_c=0 nuclei_c=0

  [[ -f "${OUTPUT_DIR}/redirect_confirmed.txt"   ]] && redirect_count=$(wc -l < "${OUTPUT_DIR}/redirect_confirmed.txt" | tr -d '\n\r')
  [[ -f "${OUTPUT_DIR}/403_bypass_confirmed.txt" ]] && bypass_200=$(wc -l < "${OUTPUT_DIR}/403_bypass_confirmed.txt" | tr -d '\n\r')
  [[ -f "${OUTPUT_DIR}/403_bypass_suspicious.txt" ]] && bypass_3xx=$(wc -l < "${OUTPUT_DIR}/403_bypass_suspicious.txt" | tr -d '\n\r')
  [[ -f "${GF_DIR}/xss.txt"        ]] && xss_c=$(wc     -l < "${GF_DIR}/xss.txt"        2>/dev/null | tr -d '\n\r' || echo 0)
  [[ -f "${GF_DIR}/sqli.txt"       ]] && sqli_c=$(wc    -l < "${GF_DIR}/sqli.txt"       2>/dev/null | tr -d '\n\r' || echo 0)
  [[ -f "${GF_DIR}/lfi.txt"        ]] && lfi_c=$(wc     -l < "${GF_DIR}/lfi.txt"        2>/dev/null | tr -d '\n\r' || echo 0)
  [[ -f "${GF_DIR}/rce.txt"        ]] && rce_c=$(wc     -l < "${GF_DIR}/rce.txt"        2>/dev/null | tr -d '\n\r' || echo 0)
  [[ -f "${GF_DIR}/ssti.txt"       ]] && ssti_c=$(wc    -l < "${GF_DIR}/ssti.txt"       2>/dev/null | tr -d '\n\r' || echo 0)
  [[ -f "${GF_DIR}/idor.txt"       ]] && idor_c=$(wc    -l < "${GF_DIR}/idor.txt"       2>/dev/null | tr -d '\n\r' || echo 0)
  [[ -f "${GF_DIR}/debug.txt"      ]] && debug_c=$(wc   -l < "${GF_DIR}/debug.txt"      2>/dev/null | tr -d '\n\r' || echo 0)
  [[ -f "${GF_DIR}/aws.txt"        ]] && aws_c=$(wc     -l < "${GF_DIR}/aws.txt"        2>/dev/null | tr -d '\n\r' || echo 0)
  [[ -f "${GF_DIR}/tokens.txt"     ]] && tokens_c=$(wc  -l < "${GF_DIR}/tokens.txt"     2>/dev/null | tr -d '\n\r' || echo 0)
  [[ -f "${GF_DIR}/cors.txt"       ]] && cors_c=$(wc    -l < "${GF_DIR}/cors.txt"       2>/dev/null | tr -d '\n\r' || echo 0)
  [[ -f "${GF_DIR}/firebase.txt"   ]] && firebase_c=$(wc -l < "${GF_DIR}/firebase.txt"  2>/dev/null | tr -d '\n\r' || echo 0)
  [[ -f "${GF_DIR}/s3-buckets.txt" ]] && s3_c=$(wc     -l < "${GF_DIR}/s3-buckets.txt" 2>/dev/null | tr -d '\n\r' || echo 0)
  [[ -f "${GF_DIR}/takeovers.txt"  ]] && takeover_c=$(wc -l < "${GF_DIR}/takeovers.txt" 2>/dev/null | tr -d '\n\r' || echo 0)
  [[ -f "${OUTPUT_DIR}/nuclei_confirmed.txt" ]] && nuclei_c=$(wc -l < "${OUTPUT_DIR}/nuclei_confirmed.txt" 2>/dev/null | tr -d '\n\r' || echo 0)

  # Elapsed time — uses START_EPOCH so no GNU date -d parsing needed
  local elapsed_min; elapsed_min=$(( ($(date +%s) - START_EPOCH) / 60 ))

  local SUMMARY="${OUTPUT_DIR}/JACKPOT_SUMMARY.txt"
  {
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║          💰  JACKPOT SCAN COMPLETE  💰               ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo ""
    echo "  Finished : $(date)"
    echo "  Target   : ${RECON_DIR}"
    echo "  Results  : ${OUTPUT_DIR}"
    echo "  Elapsed  : ${elapsed_min} minutes"
    echo ""

    echo "  ════════════════════════════════════════════════════"
    echo "   FINDINGS SUMMARY"
    echo "  ════════════════════════════════════════════════════"
    echo ""

    local has_p1=false
    [[ "${redirect_count:-0}" -gt 0 ]] && { has_p1=true; printf "  ${P1_COLOR}%-45s${NC} %s\n" "Open Redirects Confirmed"     "$redirect_count"; }
    [[ "${rce_c:-0}"       -gt 0 ]]     && { has_p1=true; printf "  ${P1_COLOR}%-45s${NC} %s\n" "RCE Candidates (gf)"          "$rce_c"; }
    [[ "${nuclei_c:-0}"    -gt 0 ]]     && { has_p1=true; printf "  ${P1_COLOR}%-45s${NC} %s\n" "Nuclei Verified Vulns"        "$nuclei_c"; }
    [[ "${takeover_c:-0}"  -gt 0 ]]     && { has_p1=true; printf "  ${P1_COLOR}%-45s${NC} %s\n" "Subdomain Takeover Candidates" "$takeover_c"; }
    [[ "${aws_c:-0}"       -gt 0 ]]     && { has_p1=true; printf "  ${P1_COLOR}%-45s${NC} %s\n" "AWS Keys Exposed"             "$aws_c"; }
    $has_p1 || echo "  (no P1 findings)"
    echo ""

    local has_p2=false
    [[ "${bypass_200:-0}"  -gt 0 ]] && { has_p2=true; printf "  ${P2_COLOR}%-45s${NC} %s\n" "403 Bypass Confirmed (200)"   "$bypass_200"; }
    [[ "${bypass_3xx:-0}"  -gt 0 ]] && { has_p2=true; printf "  ${P2_COLOR}%-45s${NC} %s\n" "403 Bypass Suspicious (3xx)"  "$bypass_3xx"; }
    [[ "${ssti_c:-0}"      -gt 0 ]] && { has_p2=true; printf "  ${P2_COLOR}%-45s${NC} %s\n" "SSTI Candidates (gf)"         "$ssti_c"; }
    [[ "${sqli_c:-0}"      -gt 0 ]] && { has_p2=true; printf "  ${P2_COLOR}%-45s${NC} %s\n" "SQLi Candidates (gf)"         "$sqli_c"; }
    [[ "${tokens_c:-0}"    -gt 0 ]] && { has_p2=true; printf "  ${P2_COLOR}%-45s${NC} %s\n" "Secrets / Tokens (gf)"        "$tokens_c"; }
    [[ "${cors_c:-0}"      -gt 0 ]] && { has_p2=true; printf "  ${P2_COLOR}%-45s${NC} %s\n" "CORS Misconfigs (gf)"         "$cors_c"; }
    $has_p2 || echo "  (no P2 findings)"
    echo ""

    local has_p3=false
    [[ "${idor_c:-0}"     -gt 0 ]] && { has_p3=true; printf "  ${P3_COLOR}%-45s${NC} %s\n" "IDOR Candidates (gf)"         "$idor_c"; }
    [[ "${lfi_c:-0}"      -gt 0 ]] && { has_p3=true; printf "  ${P3_COLOR}%-45s${NC} %s\n" "LFI Candidates (gf)"          "$lfi_c"; }
    [[ "${xss_c:-0}"      -gt 0 ]] && { has_p3=true; printf "  ${P3_COLOR}%-45s${NC} %s\n" "XSS Candidates (gf)"          "$xss_c"; }
    [[ "${debug_c:-0}"    -gt 0 ]] && { has_p3=true; printf "  ${P3_COLOR}%-45s${NC} %s\n" "Debug Endpoints (gf)"         "$debug_c"; }
    [[ "${firebase_c:-0}" -gt 0 ]] && { has_p3=true; printf "  ${P3_COLOR}%-45s${NC} %s\n" "Firebase DBs (gf)"            "$firebase_c"; }
    [[ "${s3_c:-0}"       -gt 0 ]] && { has_p3=true; printf "  ${P3_COLOR}%-45s${NC} %s\n" "S3 Buckets (gf)"              "$s3_c"; }
    $has_p3 || echo "  (no P3 findings)"
    echo ""

    echo "  ── CDN / Cloud Hosting Check ───────────────────────"
    echo "  (dig +short CNAME on findings to detect CDN-mirrored hosts)"
    cdn_warn=""
    for f in "${OUTPUT_DIR}/redirect_confirmed.txt" \
             "${OUTPUT_DIR}/403_bypass_real.txt" \
             "${OUTPUT_DIR}/nuclei_confirmed.txt" \
             "${OUTPUT_DIR}/ssti_confirmed.txt" \
             "${OUTPUT_DIR}/cors_confirmed.txt"; do
      [[ ! -f "$f" || ! -s "$f" ]] && continue
      while IFS= read -r line; do
        dom=$(echo "$line" | grep -oP 'https?://[^/\s:]+' | head -1 | sed 's|https\?://||')
        [[ -z "$dom" ]] && continue
        cname=$(dig +short CNAME "$dom" 2>/dev/null | head -1 || true)
        case "$cname" in
          *cloudfront*) cdn_warn="${cdn_warn},${dom}→${cname}" ;;
          *cloudflare*) cdn_warn="${cdn_warn},${dom}→${cname}" ;;
          *akamai*)     cdn_warn="${cdn_warn},${dom}→${cname}" ;;
          *fastly*)     cdn_warn="${cdn_warn},${dom}→${cname}" ;;
        esac
      done < "$f" 2>/dev/null
    done
    if [[ -n "$cdn_warn" ]]; then
      echo "  ${YELLOW}⚠  These findings resolve to CDN providers (not origin):${NC}"
      IFS=',' read -ra warns <<< "$cdn_warn"
      for w in "${warns[@]}"; do
        [[ -n "$w" ]] && echo "     ⚠  $w"
      done
    else
      echo "  ${GREEN}✓${NC}  No CDN-mirrored domains detected in findings."
    fi
    echo ""

    echo "  ════════════════════════════════════════════════════"
    echo "   ACTION PLAN"
    echo "  ════════════════════════════════════════════════════"
    echo ""

    local step=1
    [[ "${redirect_count:-0}" -gt 0 ]] && {
      echo "  ${P1_COLOR}Step ${step}: Confirm Open Redirects${NC}"
      echo "     → ${OUTPUT_DIR}/redirect_confirmed.txt"
      echo "     💡 Swap 'evil.com' for your own domain to prove impact"
      echo "     💡 Chain with OAuth flows for maximum severity"
      echo ""; step=$((step+1)); }
    [[ "${bypass_200:-0}" -gt 0 ]] && {
      echo "  ${P2_COLOR}Step ${step}: Review 403 Bypass (Phase 6b verified)${NC}"
      echo "     → ${OUTPUT_DIR}/403_bypass_real.txt  (passed body check)"
      echo "     → ${OUTPUT_DIR}/403_bypass_confirmed.txt  (all raw matches)"
      echo "     💡 Check what's behind the bypass — admin panels? Config?"
      echo "     💡 Skip entries in 403_bypass_suspect_soft404.txt (likely WAF)"
      echo ""; step=$((step+1)); }
    [[ "${bypass_3xx:-0}" -gt 0 ]] && {
      echo "  ${P2_COLOR}Step ${step}: Investigate Suspicious 403 Redirects${NC}"
      echo "     → ${OUTPUT_DIR}/403_bypass_suspicious.txt"
      echo "     💡 Different size from baseline → manual Burp testing"
      echo ""; step=$((step+1)); }
    [[ "${nuclei_c:-0}" -gt 0 ]] && {
      echo "  ${P1_COLOR}Step ${step}: Review Nuclei Verified Vulnerabilities${NC}"
      echo "     → ${OUTPUT_DIR}/nuclei_confirmed.txt"
      echo "     💡 Auto-confirmed (medium/high/critical only) — report now"
      echo ""; step=$((step+1)); }
    [[ "${rce_c:-0}" -gt 0 || "${sqli_c:-0}" -gt 0 || "${ssti_c:-0}" -gt 0 ]] && {
      echo "  ${P2_COLOR}Step ${step}: Manually test GF injection candidates${NC}"
      [[ "${rce_c:-0}"  -gt 0 ]] && echo "     💡 nuclei -severity high,critical -tags rce   -l ${GF_DIR}/rce.txt"
      [[ "${sqli_c:-0}" -gt 0 ]] && echo "     💡 nuclei -severity high,critical -tags sqli  -l ${GF_DIR}/sqli.txt"
      [[ "${ssti_c:-0}" -gt 0 ]] && echo "     💡 nuclei -severity high,critical -tags ssti  -l ${GF_DIR}/ssti.txt"
      echo ""; step=$((step+1)); }
    [[ "${takeover_c:-0}" -gt 0 ]] && {
      echo "  ${P1_COLOR}Step ${step}: Check Subdomain Takeover Candidates${NC}"
      echo "     💡 nuclei -t takeovers/ -l ${GF_DIR}/takeovers.txt"
      echo ""; step=$((step+1)); }
    [[ "${aws_c:-0}" -gt 0 ]] && {
      echo "  ${P1_COLOR}Step ${step}: Verify AWS Key Exposure${NC}"
      echo "     → ${GF_DIR}/aws.txt"
      echo "     💡 Look for AKIA* keys — test with aws sts get-caller-identity"
      echo ""; step=$((step+1)); }
    [[ "${tokens_c:-0}" -gt 0 ]] && {
      echo "  ${P2_COLOR}Step ${step}: Review Exposed Tokens / Secrets${NC}"
      echo "     → ${GF_DIR}/tokens.txt"
      echo "     💡 API keys, JWTs, auth tokens in source / responses"
      echo ""; step=$((step+1)); }
    [[ "${cors_c:-0}" -gt 0 ]] && {
      echo "  ${P2_COLOR}Step ${step}: Test CORS Misconfigurations${NC}"
      echo "     → ${GF_DIR}/cors.txt"
      echo "     💡 Check Origin reflection → cross-origin data theft"
      echo ""; step=$((step+1)); }
    [[ "${idor_c:-0}" -gt 0 || "${lfi_c:-0}" -gt 0 ]] && {
      echo "  ${P3_COLOR}Step ${step}: Manual Parameter Testing${NC}"
      [[ "${idor_c:-0}" -gt 0 ]] && echo "     💡 IDOR: enumerate IDs with Burp Intruder"
      [[ "${lfi_c:-0}"  -gt 0 ]] && echo "     💡 LFI:  ../../../../etc/passwd chains"
      echo ""; step=$((step+1)); }
    [[ "${xss_c:-0}" -gt 0 ]] && {
      echo "  ${P3_COLOR}Step ${step}: XSS Candidate Review${NC}"
      echo "     → ${GF_DIR}/xss.txt"
      echo "     💡 Test with <script>alert(document.domain)</script>"
      echo ""; step=$((step+1)); }
    [[ -f "${OUTPUT_DIR}/response_analysis.txt" ]] && {
      echo "  ${P3_COLOR}Step ${step}: Review Response Analysis${NC}"
      echo "     → ${OUTPUT_DIR}/response_analysis.txt"
      echo "     💡 Check tech stack for known CVEs"
      echo "     💡 Login panels → default creds, brute-force, bypass"
      echo ""; }

    echo "  ════════════════════════════════════════════════════"
    echo "   OUTPUT FILES"
    echo "  ════════════════════════════════════════════════════"
    echo ""
    for f in "$OUTPUT_DIR"/*.txt; do
      [[ -f "$f" ]] || continue
      local fname; fname=$(basename "$f")
      local flines; flines=$(wc -l < "$f" 2>/dev/null || echo 0)
      printf "  %-50s %s lines\n" "${fname}:" "$flines"
    done
    echo ""

    echo "  ════════════════════════════════════════════════════"
    echo "   PRO TIPS"
    echo "  ════════════════════════════════════════════════════"
    echo ""
    echo "  💡 Use -j 20 on fast networks, -d 1 on WAF-heavy targets"
    echo "  💡 Replace 'evil.com' with a Burp Collaborator / interactsh URL"
    echo "  💡 Always inspect 403-bypass 200s in Burp — soft-404s are common"
    echo "  💡 Run nuclei with -ud ~/.nuclei-templates after updating templates"
    echo "  💡 Pipe gf_results/ files into dalfox / sqlmap for deeper testing"
    echo ""

    echo "╔══════════════════════════════════════════════════════╗"
    echo "║   🎰  Happy hunting. Stay in scope. Stay ethical.    ║"
    echo "╚══════════════════════════════════════════════════════╝"

  } | tee "$SUMMARY" | tee -a "$LOG_FILE"
}

# ─── MAIN ────────────────────────────────────────────────────
main() {
  parse_args "$@"
  print_banner
  check_tools
  validate_files
  extract_target_domains
  info "In-scope domains: $(wc -l < "${OUTPUT_DIR}/.in_scope_domains.txt" 2>/dev/null || echo 0) entries"
  run_gf_scans
  run_redirect_chain
  run_403_bypass
  run_response_analysis
  run_403_bypass_verify
  run_ssti_auto_test
  run_cors_auto_test
  run_nuclei_verification
  print_summary
}

main "$@"