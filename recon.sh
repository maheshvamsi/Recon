#!/bin/bash

# ==============================================
# Subdomain Recon Tool v2.2 - Fixed URL Collection
# ==============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "=========================================="
echo "   Subdomain Recon Tool v2.2"
echo "   Fixed URL Collection"
echo "=========================================="
echo -e "${NC}"

# Configuration — auto-detect CPU count
MAX_PARALLEL=$(nproc 2>/dev/null || echo 4)
HTTPX_THREADS=50
HTTPX_RATE_LIMIT=150
HTTPX_TIMEOUT=15
KATANA_DEPTH=3
JS_DL_CONCURRENCY=15

# Help function
show_help() {
    echo -e "${GREEN}Subdomain Recon Tool v2.2${NC}"
    echo ""
    echo -e "${YELLOW}Usage:${NC}"
    echo -e "  $0 -u <domain>           Scan a single domain"
    echo -e "  $0 -l <domains_file>     Scan multiple domains from a file"
    echo -e "  $0 -js <results_dir>     Run JS extraction only"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  --resume                 Resume a previous interrupted scan"
    echo -e "  --skip-js                Skip JavaScript extraction"
    echo -e "  --skip-crawl             Skip katana crawling"
    echo -e "  -h, --help               Show this help"
    exit 0
}

# Parse arguments
RESUME=false
BACKUP_PREVIOUS=true
SKIP_JS=false
SKIP_CRAWL=false
JS_ONLY=false
JS_DIR=""
INPUT=""
INPUT_TYPE=""
PREVIOUS_SCAN=""
BACKUP_DIR=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help) show_help ;;
        -u) INPUT_TYPE="domain"; INPUT="$2"; shift 2 ;;
        -l) INPUT_TYPE="list"; INPUT="$2"; shift 2 ;;
        -js) JS_ONLY=true; JS_DIR="$2"; shift 2 ;;
        --resume) RESUME=true; shift ;;
        --no-backup) BACKUP_PREVIOUS=false; shift ;;
        --skip-js) SKIP_JS=true; shift ;;
        --skip-crawl) SKIP_CRAWL=true; shift ;;
        *) echo -e "${RED}[!] Unknown option: $1${NC}"; exit 1 ;;
    esac
done

# JS-only mode
if [ "$JS_ONLY" = true ]; then
    if [ -z "$JS_DIR" ]; then
        echo -e "${RED}[!] -js requires a results directory${NC}"
        exit 1
    fi
    echo -e "${BLUE}[*] JS extraction mode on: ${JS_DIR}${NC}"
    JS_OUT="${JS_DIR}/js_extracted"
    mkdir -p "$JS_OUT" "${JS_OUT}/raw"

    # Filter JS URLs from cleaned results
    if [ -f "${JS_DIR}/urls_cleaned.txt" ]; then
        grep -iE '\.js(\?|$)' "${JS_DIR}/urls_cleaned.txt" | sort -u > "${JS_OUT}/js_urls.txt"
        JS_COUNT=$(wc -l < "${JS_OUT}/js_urls.txt")
        echo -e "${GREEN}[✓] JS files found: $JS_COUNT${NC}"

        # Download JS files and extract endpoints/patterns
        if [ "$JS_COUNT" -gt 0 ]; then
            echo -e "${YELLOW}[*] Downloading JS files (concurrency: $JS_DL_CONCURRENCY)...${NC}"
            > "${JS_OUT}/js_endpoints.txt"
            < "${JS_OUT}/js_urls.txt" xargs -d '\n' -P "$JS_DL_CONCURRENCY" -I{} bash -c '
                fname=$(printf "%s" "$1" | md5sum | cut -d" " -f1)
                curl -sL --max-time 10 -- "$1" -o "'"${JS_OUT}"'/raw/${fname}.js" 2>/dev/null
            ' _ {}

            # Extract endpoints from downloaded JS
            grep -oP '(?:"[^"]*"|'\''[^'\'']*'\'')?https?://[^"'\''<> ]+' \
                "${JS_OUT}/raw/"*.js 2>/dev/null | \
                sort -u > "${JS_OUT}/js_endpoints.txt"
            EP_COUNT=$(wc -l < "${JS_OUT}/js_endpoints.txt")
            echo -e "${GREEN}[✓] Endpoints extracted: $EP_COUNT${NC}"

            # Find API keys / secrets patterns
            grep -oP '(?:api[Kk]ey|api[_-]?secret|access[_-]?token|secret|token|password)[:=]\s*["'\'']?([^"'\''&,\s]+)' \
                "${JS_OUT}/raw/"*.js 2>/dev/null | \
                sort -u > "${JS_OUT}/js_secrets.txt"
            SEC_COUNT=$(wc -l < "${JS_OUT}/js_secrets.txt")
            echo -e "${GREEN}[✓] Potential secrets: $SEC_COUNT${NC}"
        fi
    else
        echo -e "${YELLOW}[!] No url_cleaned.txt in ${JS_DIR}${NC}"
    fi
    echo -e "${GREEN}[*] JS extraction done → ${JS_OUT}${NC}"
    exit 0
fi

# Validate input
if [ "$RESUME" = false ] && [ -z "$INPUT" ]; then
    echo -e "${RED}[!] No input provided${NC}"
    show_help
fi

# Tool check
check_tools() {
    MISSING=0
    echo -e "${BLUE}[*] Checking required tools...${NC}"
    for tool in subfinder assetfinder httpx gau waybackurls jq curl uro; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}[!] $tool not installed${NC}"
            MISSING=1
        else
            echo -e "${GREEN}[✓] $tool${NC}"
        fi
    done
    [ "$MISSING" = 1 ] && exit 1

    # ── Optional tools (install for better coverage) ──────────────────────────
    echo ""
    echo -e "${BLUE}[*] Checking optional tools...${NC}"
    for tool in chaos findomain katana timeout; do
        if command -v "$tool" &> /dev/null; then
            echo -e "${GREEN}[✓] $tool${NC}"
        else
            echo -e "${YELLOW}[~] $tool not found (optional — skipping)${NC}"
        fi
    done
    # ──────────────────────────────────────────────────────────────────────────
    echo ""
}

# crt.sh function — FIXED
# Changes: JSON validation before piping to jq, retry with back-off,
#          User-Agent + --compressed headers to avoid empty/HTML responses
crtsh() {
    local domain="$1"
    local attempt=1
    local max_attempts=2
    local response

    while [ $attempt -le $max_attempts ]; do
        response=$(curl -s --max-time 30 --compressed \
            -H "User-Agent: Mozilla/5.0 (compatible; recon-tool/2.2)" \
            "https://crt.sh/?q=%.${domain}&output=json" 2>/dev/null)

        if [ -n "$response" ] && echo "$response" | jq -e 'type == "array"' &>/dev/null; then
            echo "$response" | jq -r '.[].name_value' 2>/dev/null | \
                sed 's/\*\.//g' | tr ',' '\n' | \
                grep -v "@" | grep "\." | sort -u
            return 0
        fi

        echo -e "${YELLOW}[!] [$domain] crt.sh attempt $attempt/$max_attempts failed, retrying in ${attempt}s...${NC}" >&2
        sleep "$attempt"
        ((attempt++))
    done

    echo -e "${RED}[!] [$domain] crt.sh failed after $max_attempts attempts — skipping${NC}" >&2
    return 1
}

# Output directory
create_output_dir() {
    local domain_name="$1"
    local timestamp=$(date +%Y-%m-%d_%H-%M-%S)
    local base_name="recon_${domain_name}"
    if [ "$INPUT_TYPE" == "list" ]; then
        base_name="recon_multi"
    fi

    # Backup previous — use printf to strip ./ prefix from find output
    local latest_dir=$(find . -maxdepth 1 -type d -name "${base_name}_*" -printf '%P\n' 2>/dev/null | sort -r | head -1)
    if [ -n "$latest_dir" ] && [ "$BACKUP_PREVIOUS" = true ]; then
        mkdir -p backups
        cp -r "$latest_dir" "backups/${latest_dir}_backup_${timestamp}"
        PREVIOUS_SCAN="$latest_dir"
    fi

    OUTPUT_DIR="${base_name}_${timestamp}"
    mkdir -p "$OUTPUT_DIR"
    echo "$OUTPUT_DIR"
}

# Subdomain enumeration
enumerate_subdomains() {
    local domain=$1
    local output_dir=$2
    local temp_dir="${output_dir}/.temp_${domain//./_}"
    mkdir -p "$temp_dir"

    echo -e "${BLUE}[*] [$domain] Starting enumeration...${NC}"

    # Subfinder
    echo -e "${YELLOW}[*] [$domain] Running subfinder...${NC}"
    subfinder -d "$domain" -silent -o "${temp_dir}/subfinder.txt" 2>/dev/null || touch "${temp_dir}/subfinder.txt"
    echo -e "${GREEN}[✓] [$domain] Subfinder: $(wc -l < "${temp_dir}/subfinder.txt")${NC}"

    # Assetfinder
    echo -e "${YELLOW}[*] [$domain] Running assetfinder...${NC}"
    timeout 120 assetfinder --subs-only "$domain" > "${temp_dir}/assetfinder.txt" 2>/dev/null || touch "${temp_dir}/assetfinder.txt"
    echo -e "${GREEN}[✓] [$domain] Assetfinder: $(wc -l < "${temp_dir}/assetfinder.txt")${NC}"

    # crt.sh (fixed)
    echo -e "${YELLOW}[*] [$domain] Running crt.sh...${NC}"
    crtsh "$domain" > "${temp_dir}/crtsh.txt" || touch "${temp_dir}/crtsh.txt"
    echo -e "${GREEN}[✓] [$domain] crt.sh: $(wc -l < "${temp_dir}/crtsh.txt")${NC}"

    # ── NEW: Chaos ─────────────────────────────────────────────────────────────
    if command -v chaos &> /dev/null; then
        echo -e "${YELLOW}[*] [$domain] Running chaos...${NC}"
        chaos -d "$domain" -silent -o "${temp_dir}/chaos.txt" 2>/dev/null || touch "${temp_dir}/chaos.txt"
        echo -e "${GREEN}[✓] [$domain] Chaos: $(wc -l < "${temp_dir}/chaos.txt")${NC}"
    else
        touch "${temp_dir}/chaos.txt"
    fi

    # ── NEW: Findomain ──────────────────────────────────────────────────────────
    if command -v findomain &> /dev/null; then
        echo -e "${YELLOW}[*] [$domain] Running findomain...${NC}"
        findomain -t "$domain" -q 2>/dev/null > "${temp_dir}/findomain.txt" || touch "${temp_dir}/findomain.txt"
        echo -e "${GREEN}[✓] [$domain] Findomain: $(wc -l < "${temp_dir}/findomain.txt")${NC}"
    else
        touch "${temp_dir}/findomain.txt"
    fi
    # ───────────────────────────────────────────────────────────────────────────

    # Combine
    sort -u "${temp_dir}"/*.txt 2>/dev/null > "${output_dir}/.all_subdomains_${domain//./_}.txt"
    echo -e "${GREEN}[✓] [$domain] Total: $(wc -l < "${output_dir}/.all_subdomains_${domain//./_}.txt")${NC}"
}

# MAIN
check_tools

# Setup output
if [ "$RESUME" = true ]; then
    OUTPUT_DIR=$(find . -maxdepth 1 -type d -name 'recon_*' -printf '%P\n' 2>/dev/null | sort -r | head -1)
    [ -z "$OUTPUT_DIR" ] && echo -e "${RED}[!] No previous scan${NC}" && exit 1
    echo -e "${GREEN}[*] Resuming: $OUTPUT_DIR${NC}"
else
    if [ "$INPUT_TYPE" == "list" ]; then
        FIRST_DOMAIN=$(head -1 "$INPUT" | xargs)
        OUTPUT_DIR=$(create_output_dir "$FIRST_DOMAIN")
    else
        OUTPUT_DIR=$(create_output_dir "$INPUT")
    fi
    echo -e "${GREEN}[*] Output: $OUTPUT_DIR${NC}"
fi

# On resume, skip enumeration if already done
if [ "$RESUME" = true ] && [ -f "${OUTPUT_DIR}/all_subdomains.txt" ] && [ -s "${OUTPUT_DIR}/all_subdomains.txt" ]; then
    echo -e "${GREEN}[*] Subdomains already enumerated, skipping...${NC}"
    TOTAL_SUBDOMAINS=$(wc -l < "${OUTPUT_DIR}/all_subdomains.txt")
else
    # Collect domains
    DOMAINS=()
    if [ "$INPUT_TYPE" == "list" ]; then
        while IFS= read -r domain; do
            [[ -z "$domain" || "$domain" =~ ^# ]] && continue
            DOMAINS+=("$(echo "$domain" | xargs)")
        done < "$INPUT"
    else
        DOMAINS=("$INPUT")
    fi

    # Save root domains for later use (gau --subs etc.)
    printf '%s\n' "${DOMAINS[@]}" > "${OUTPUT_DIR}/root_domains.txt"

    # Parallel enumeration
    export -f enumerate_subdomains crtsh
    export OUTPUT_DIR
    printf '%s\n' "${DOMAINS[@]}" | xargs -P "$MAX_PARALLEL" -I {} bash -c 'enumerate_subdomains "$@"' _ {} "$OUTPUT_DIR"

    # Merge subdomains
    sort -u "${OUTPUT_DIR}"/.all_subdomains_*.txt 2>/dev/null > "${OUTPUT_DIR}/all_subdomains.txt"
    TOTAL_SUBDOMAINS=$(wc -l < "${OUTPUT_DIR}/all_subdomains.txt")
    echo -e "${GREEN}[✓] Total unique subdomains: $TOTAL_SUBDOMAINS${NC}"
fi

# Ensure root_domains.txt exists for gau --subs (fallback)
if [ ! -f "${OUTPUT_DIR}/root_domains.txt" ] || [ ! -s "${OUTPUT_DIR}/root_domains.txt" ]; then
    if [ -f "${OUTPUT_DIR}/all_subdomains.txt" ]; then
        awk -F. '{print $(NF-1)"."$NF}' "${OUTPUT_DIR}/all_subdomains.txt" | sort -u \
            > "${OUTPUT_DIR}/root_domains.txt"
    fi
fi

# HTTPX (skip on resume if already done)
if [ "$RESUME" = false ] || [ ! -f "${OUTPUT_DIR}/httpx_results.txt" ] || [ ! -s "${OUTPUT_DIR}/httpx_results.txt" ]; then
    echo -e "${YELLOW}[*] Probing subdomains with httpx...${NC}"
    httpx -l "${OUTPUT_DIR}/all_subdomains.txt" \
        -threads "$HTTPX_THREADS" -rate-limit "$HTTPX_RATE_LIMIT" \
        -retries 2 -timeout "$HTTPX_TIMEOUT" \
        -follow-redirects -random-agent \
        -status-code -title -tech-detect -content-length \
        -o "${OUTPUT_DIR}/httpx_results.txt" -silent 2>/dev/null
else
    echo -e "${GREEN}[*] httpx results exist, skipping...${NC}"
fi

grep -oP 'https?://[^\s]+' "${OUTPUT_DIR}/httpx_results.txt" 2>/dev/null | sort -u > "${OUTPUT_DIR}/live_subdomains.txt"
LIVE_COUNT=$(wc -l < "${OUTPUT_DIR}/live_subdomains.txt")
echo -e "${GREEN}[✓] Live subdomains: $LIVE_COUNT${NC}"

# ==============================================
# URL COLLECTION - FIXED
# ==============================================

echo -e "${BLUE}[*] Collecting URLs from live subdomains...${NC}"

if [ ! -f "${OUTPUT_DIR}/.urls_collected" ] || [ "$RESUME" = false ]; then
    > "${OUTPUT_DIR}/urls_raw.txt"

    # Extract clean domains (remove http://, https://, paths)
    echo -e "${YELLOW}[*] Cleaning domain list...${NC}"
    < "${OUTPUT_DIR}/live_subdomains.txt" \
        sed -E 's#^https?://##' | \
        cut -d'/' -f1 | \
        sort -u > "${OUTPUT_DIR}/domains_clean.txt"

    DOMAIN_COUNT=$(wc -l < "${OUTPUT_DIR}/domains_clean.txt")
    echo -e "${GREEN}[✓] Clean domains: $DOMAIN_COUNT${NC}"

    # Run URL collection in parallel
    # gau --subs on root domains is MUCH faster than per-subdomain iteration
    echo -e "${YELLOW}[*] Running historical URL collection (gau --subs + waybackurls)...${NC}"
    < "${OUTPUT_DIR}/root_domains.txt" gau --subs --threads 10 2>/dev/null > "${OUTPUT_DIR}/gau_temp.txt" &
    GAU_PID=$!

    if [ "$SKIP_CRAWL" = false ]; then
        < "${OUTPUT_DIR}/domains_clean.txt" waybackurls 2>/dev/null > "${OUTPUT_DIR}/wayback_temp.txt" &
        WAYBACK_PID=$!
    fi

    wait $GAU_PID
    [ "$SKIP_CRAWL" = false ] && wait $WAYBACK_PID

    # Combine results
    < "${OUTPUT_DIR}/gau_temp.txt" cat >> "${OUTPUT_DIR}/urls_raw.txt" 2>/dev/null
    [ "$SKIP_CRAWL" = false ] && < "${OUTPUT_DIR}/wayback_temp.txt" cat >> "${OUTPUT_DIR}/urls_raw.txt" 2>/dev/null
    rm -f "${OUTPUT_DIR}/gau_temp.txt"
    [ "$SKIP_CRAWL" = false ] && rm -f "${OUTPUT_DIR}/wayback_temp.txt"

    RAW_COUNT=$(wc -l < "${OUTPUT_DIR}/urls_raw.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Historical URLs collected: $RAW_COUNT${NC}"

    # Katana (optional)
    if [ "$SKIP_CRAWL" = false ] && command -v katana &> /dev/null; then
        echo -e "${YELLOW}[*] Running katana...${NC}"
        katana -list "${OUTPUT_DIR}/live_subdomains.txt" \
            -depth "$KATANA_DEPTH" -jc -silent \
            -o "${OUTPUT_DIR}/katana_urls.txt" 2>/dev/null

        if [ -f "${OUTPUT_DIR}/katana_urls.txt" ]; then
            < "${OUTPUT_DIR}/katana_urls.txt" cat >> "${OUTPUT_DIR}/urls_raw.txt"
            KATANA_COUNT=$(wc -l < "${OUTPUT_DIR}/katana_urls.txt")
            echo -e "${GREEN}[✓] Katana found: $KATANA_COUNT fresh URLs${NC}"
        fi
    fi

    touch "${OUTPUT_DIR}/.urls_collected"
fi

# Filter with uro
if [ ! -f "${OUTPUT_DIR}/.urls_cleaned" ] || [ "$RESUME" = false ]; then
    if [ -f "${OUTPUT_DIR}/urls_raw.txt" ] && [ -s "${OUTPUT_DIR}/urls_raw.txt" ]; then
        RAW_COUNT=$(wc -l < "${OUTPUT_DIR}/urls_raw.txt")
        echo -e "${YELLOW}[*] Filtering $RAW_COUNT URLs with uro...${NC}"
        < "${OUTPUT_DIR}/urls_raw.txt" uro > "${OUTPUT_DIR}/urls_cleaned.txt" 2>/dev/null
        CLEANED_COUNT=$(wc -l < "${OUTPUT_DIR}/urls_cleaned.txt")
        echo -e "${GREEN}[✓] Cleaned URLs: $CLEANED_COUNT${NC}"
        touch "${OUTPUT_DIR}/.urls_cleaned"
    else
        echo -e "${YELLOW}[!] No URLs collected${NC}"
        touch "${OUTPUT_DIR}/urls_cleaned.txt"
        touch "${OUTPUT_DIR}/.urls_cleaned"
    fi
fi

# ==============================================
# JUICY ENDPOINTS
# ==============================================

if [ -f "${OUTPUT_DIR}/urls_cleaned.txt" ] && [ -s "${OUTPUT_DIR}/urls_cleaned.txt" ]; then
    echo -e "${BLUE}[*] Extracting juicy endpoints...${NC}"

    # Parameterized URLs
    grep -E "\?.*=" "${OUTPUT_DIR}/urls_cleaned.txt" > "${OUTPUT_DIR}/parameterized_urls.txt" 2>/dev/null
    PARAM_COUNT=$(wc -l < "${OUTPUT_DIR}/parameterized_urls.txt")
    echo -e "${GREEN}[✓] Parameterized URLs: $PARAM_COUNT${NC}"

    # High-value parameters
    grep -iE "(id=|user_?id=|account=|profile=|download=|file=|path=|redirect=|url=|dest=|api|v[0-9]|graphql|swagger|admin|debug|upload|token|key)" \
        "${OUTPUT_DIR}/parameterized_urls.txt" > "${OUTPUT_DIR}/juicy_params.txt" 2>/dev/null
    JUICY_COUNT=$(wc -l < "${OUTPUT_DIR}/juicy_params.txt")
    echo -e "${GREEN}[✓] High-value: $JUICY_COUNT${NC}"

    # High priority
    grep -iE "(admin|dashboard|console|dev|staging|test|debug|backup|upload|download|api|portal|gateway|internal|private|secure)" \
        "${OUTPUT_DIR}/juicy_params.txt" > "${OUTPUT_DIR}/high_priority.txt" 2>/dev/null
    HIGH_COUNT=$(wc -l < "${OUTPUT_DIR}/high_priority.txt")
    echo -e "${GREEN}[✓] High priority: $HIGH_COUNT${NC}"

    # Attack surface
    cp "${OUTPUT_DIR}/juicy_params.txt" "${OUTPUT_DIR}/attack_surface.txt"
fi

# Response analysis
if [ -f "${OUTPUT_DIR}/httpx_results.txt" ]; then
    grep -iE "(admin|dashboard|swagger|graphql|api|v1|v2|wp-|phpmyadmin|jenkins|kibana|grafana)" \
        "${OUTPUT_DIR}/httpx_results.txt" > "${OUTPUT_DIR}/interesting_paths.txt" 2>/dev/null

    grep -E "403" "${OUTPUT_DIR}/httpx_results.txt" > "${OUTPUT_DIR}/forbidden_pages.txt" 2>/dev/null
    grep -E "500" "${OUTPUT_DIR}/httpx_results.txt" > "${OUTPUT_DIR}/error_pages.txt" 2>/dev/null
fi

# Cleanup
rm -rf "${OUTPUT_DIR}"/.temp_* 2>/dev/null
rm -f "${OUTPUT_DIR}"/.all_subdomains_*.txt 2>/dev/null

# ==============================================
# SUMMARY
# ==============================================

echo -e "\n${BLUE}=========================================="
echo "              SUMMARY"
echo "==========================================${NC}"
echo -e "${YELLOW}Subdomains:${NC} $TOTAL_SUBDOMAINS"
echo -e "${YELLOW}Live:${NC} $LIVE_COUNT"
echo -e "${YELLOW}Cleaned URLs:${NC} $(wc -l < "${OUTPUT_DIR}/urls_cleaned.txt" 2>/dev/null || echo "0")"
echo -e "${YELLOW}Attack surface:${NC} $(wc -l < "${OUTPUT_DIR}/attack_surface.txt" 2>/dev/null || echo "0")"
echo -e "\n${GREEN}Output: $OUTPUT_DIR/${NC}"
echo -e "  → ${OUTPUT_DIR}/high_priority.txt"
echo -e "  → ${OUTPUT_DIR}/juicy_params.txt"
echo -e "  → ${OUTPUT_DIR}/interesting_paths.txt"
echo -e "  → ${OUTPUT_DIR}/forbidden_pages.txt"
echo -e "${BLUE}==========================================${NC}"
