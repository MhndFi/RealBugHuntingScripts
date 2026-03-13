#!/usr/bin/env bash
set -euo pipefail

# Support both standard Go bin locations and explicit system install location.
if [[ -d "/home/mhndfi/go/bin" ]]; then
  export PATH="/home/mhndfi/go/bin:${PATH}"
fi
if [[ -d "${HOME}/go/bin" ]]; then
  export PATH="${HOME}/go/bin:${PATH}"
fi
if [[ -d "/opt/gobin" ]]; then
  export PATH="/opt/gobin:${PATH}"
fi

# Basic ANSI styling (only when attached to a terminal).
if [[ -t 1 ]]; then
  BOLD=$'\033[1m'
  CYAN=$'\033[36m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  RED=$'\033[31m'
  RESET=$'\033[0m'
else
  BOLD=""
  CYAN=""
  GREEN=""
  YELLOW=""
  RED=""
  RESET=""
fi

print_banner() {
  cat <<'BANNER'
 __  __ _   _ _   _ ____  _____ ___
|  \/  | | | | \ | |  _ \|  ___|_ _|
| |\/| | |_| |  \| | | | | |_   | |
| |  | |  _  | |\  | |_| |  _|  | |
|_|  |_|_| |_|_| \_|____/|_|   |___|
BANNER
  printf "%s%sMhndFi Recon Toolkit%s\n" "$BOLD" "$CYAN" "$RESET"
}

animate_boot() {
  local msg="Bootstrapping modules"
  local frames=("|" "/" "-" "\\")
  local i
  for ((i=0; i<20; i++)); do
    printf "\r%s[%s]%s %s" "$CYAN" "${frames[i % 4]}" "$RESET" "$msg"
    sleep 0.06
  done
  printf "\r%s[+]%s %s\n" "$GREEN" "$RESET" "$msg"
}

usage() {
  cat <<'USAGE'
Usage:
  MFrecon.sh [options] <domain>

What it does:
  One-command recon pipeline for a target domain.
  1) Enumerates subdomains (subfinder, assetfinder, amass, crt.sh, wayback)
  2) Probes live hosts and keeps useful status codes
  3) Collects URLs (wayback.sh, gau, katana) and merges corpus
  4) Extracts API/interesting/parameterized URLs
  5) Extracts JS URLs, filters important JS (default), downloads JS with wget guards
  6) Writes AI handoff file: NEXT_STEPS_AI.md

Output:
  Default:
    ~/targets/<domain>/
  Custom:
    -o, --output-dir /path/to/folder
  Key folders:
    subs, alive, urls, js, nuclei_results, burp-to

Options:
  -h, --help                          Show this help message.
  -o, --output-dir <path>             Write all recon output into this exact folder.
  --js-mode <important|all>           JS download mode. Default: important.
  --max-js-per-host <n>               Cap selected JS URLs per host in important mode. Default: 30.
  --skip-js-download                  Skip wget JS download stage but still create NEXT_STEPS_AI.md.
  --wayback-cdx-timeout <sec>         Timeout for Wayback CDX host collection. Default: 90.
  --wayback-script-timeout <sec>      Timeout for wayback.sh stages. Default: 180.
  --gau-timeout <sec>                 Timeout for gau URL collection. Default: 180.
  --katana-timeout <sec>              Timeout for katana URL collection. Default: 300.

Environment variables:
  OUTPUT_DIR
  JS_DOWNLOAD_MODE
  MAX_JS_PER_HOST
  SKIP_JS_DOWNLOAD
  WAYBACK_CDX_TIMEOUT
  WAYBACK_SCRIPT_TIMEOUT
  GAU_TIMEOUT
  KATANA_TIMEOUT

Examples:
  MFrecon.sh example.com
  MFrecon.sh https://example.com
  MFrecon.sh -o ~/recon/vfsevisa vfsevisa.com
  OUTPUT_DIR=~/recon/vfsevisa MFrecon.sh vfsevisa.com
  MFrecon.sh --js-mode all vfsevisa.com
  MFrecon.sh --max-js-per-host 15 vfsevisa.com
  MFrecon.sh --skip-js-download vfsevisa.com
  MFrecon.sh --wayback-cdx-timeout 45 --wayback-script-timeout 90 vfsevisa.com
USAGE
}

# Path helpers.
START_PWD="$(pwd)"

expand_path() {
  local path="$1"
  case "$path" in
    "~")
      printf '%s\n' "$HOME"
      ;;
    "~/"*)
      printf '%s/%s\n' "$HOME" "${path#~/}"
      ;;
    *)
      printf '%s\n' "$path"
      ;;
  esac
}

make_absolute_path() {
  local path="$1"
  if [[ "$path" == /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s/%s\n' "$START_PWD" "$path"
  fi
}

# Runtime config defaults. Can be overridden by CLI options below.
OUTPUT_DIR="${OUTPUT_DIR:-}"
JS_DOWNLOAD_MODE="${JS_DOWNLOAD_MODE:-important}"
MAX_JS_PER_HOST="${MAX_JS_PER_HOST:-30}"
SKIP_JS_DOWNLOAD="${SKIP_JS_DOWNLOAD:-0}"
WAYBACK_CDX_TIMEOUT="${WAYBACK_CDX_TIMEOUT:-90}"
WAYBACK_SCRIPT_TIMEOUT="${WAYBACK_SCRIPT_TIMEOUT:-180}"
GAU_TIMEOUT="${GAU_TIMEOUT:-180}"
KATANA_TIMEOUT="${KATANA_TIMEOUT:-300}"

DOMAIN_INPUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    -o|--output-dir)
      if [[ $# -lt 2 ]]; then
        echo "[!] Missing value for --output-dir" >&2
        usage
        exit 1
      fi
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --js-mode)
      if [[ $# -lt 2 ]]; then
        echo "[!] Missing value for --js-mode" >&2
        usage
        exit 1
      fi
      JS_DOWNLOAD_MODE="$2"
      shift 2
      ;;
    --max-js-per-host)
      if [[ $# -lt 2 ]]; then
        echo "[!] Missing value for --max-js-per-host" >&2
        usage
        exit 1
      fi
      MAX_JS_PER_HOST="$2"
      shift 2
      ;;
    --skip-js-download)
      SKIP_JS_DOWNLOAD=1
      shift
      ;;
    --wayback-cdx-timeout)
      if [[ $# -lt 2 ]]; then
        echo "[!] Missing value for --wayback-cdx-timeout" >&2
        usage
        exit 1
      fi
      WAYBACK_CDX_TIMEOUT="$2"
      shift 2
      ;;
    --wayback-script-timeout)
      if [[ $# -lt 2 ]]; then
        echo "[!] Missing value for --wayback-script-timeout" >&2
        usage
        exit 1
      fi
      WAYBACK_SCRIPT_TIMEOUT="$2"
      shift 2
      ;;
    --gau-timeout)
      if [[ $# -lt 2 ]]; then
        echo "[!] Missing value for --gau-timeout" >&2
        usage
        exit 1
      fi
      GAU_TIMEOUT="$2"
      shift 2
      ;;
    --katana-timeout)
      if [[ $# -lt 2 ]]; then
        echo "[!] Missing value for --katana-timeout" >&2
        usage
        exit 1
      fi
      KATANA_TIMEOUT="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "[!] Unknown option: $1" >&2
      usage
      exit 1
      ;;
    *)
      if [[ -z "${DOMAIN_INPUT}" ]]; then
        DOMAIN_INPUT="$1"
      else
        echo "[!] Unexpected extra argument: $1" >&2
        usage
        exit 1
      fi
      shift
      ;;
  esac
done

if [[ -z "${DOMAIN_INPUT}" && $# -gt 0 ]]; then
  DOMAIN_INPUT="$1"
  shift
fi

if [[ $# -gt 0 ]]; then
  echo "[!] Unexpected extra argument(s): $*" >&2
  usage
  exit 1
fi

if [[ -z "${DOMAIN_INPUT}" ]]; then
  usage
  exit 1
fi

if [[ "${JS_DOWNLOAD_MODE}" != "important" && "${JS_DOWNLOAD_MODE}" != "all" ]]; then
  echo "[!] Invalid --js-mode: ${JS_DOWNLOAD_MODE} (use important or all)" >&2
  exit 1
fi

if [[ "${SKIP_JS_DOWNLOAD}" != "0" && "${SKIP_JS_DOWNLOAD}" != "1" ]]; then
  echo "[!] Invalid SKIP_JS_DOWNLOAD value: ${SKIP_JS_DOWNLOAD} (use 0 or 1)" >&2
  exit 1
fi

for NUM_OPT in MAX_JS_PER_HOST WAYBACK_CDX_TIMEOUT WAYBACK_SCRIPT_TIMEOUT GAU_TIMEOUT KATANA_TIMEOUT; do
  if ! [[ "${!NUM_OPT}" =~ ^[0-9]+$ ]]; then
    echo "[!] Invalid numeric value for ${NUM_OPT}: ${!NUM_OPT}" >&2
    exit 1
  fi
done

DOMAIN="${DOMAIN_INPUT#http://}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"
DOMAIN="${DOMAIN%%:*}"
DOMAIN="${DOMAIN%.}"
DOMAIN="${DOMAIN,,}"

# Allow inputs like *.example.com from copied commands.
if [[ "$DOMAIN" == \*.* ]]; then
  DOMAIN="${DOMAIN#*.}"
fi

# Keep target as root domain if user passes a common host like www.example.com.
if [[ "$DOMAIN" == www.* ]]; then
  DOMAIN="${DOMAIN#www.}"
fi

if [[ -z "$DOMAIN" ]]; then
  echo "[!] Invalid domain input: $DOMAIN_INPUT" >&2
  exit 1
fi

if [[ "$DOMAIN" =~ [^a-z0-9.-] ]]; then
  echo "[!] Domain contains unsupported characters: $DOMAIN" >&2
  exit 1
fi

trap 'printf "\n[!] Interrupted by user.\n" >&2; exit 130' INT

print_banner
animate_boot

WAYBACK_SCRIPT="/home/mhndfi/Tools/wayback.sh"

REQUIRED_TOOLS=(
  subfinder
  assetfinder
  amass
  curl
  jq
  httpx
  gau
  katana
  wget
  timeout
  sed
  awk
  grep
  sort
  cut
  tee
  mktemp
)

MISSING=()
for tool in "${REQUIRED_TOOLS[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    MISSING+=("$tool")
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "[!] Missing required tools: ${MISSING[*]}" >&2
  exit 1
fi

if [[ ! -x "${WAYBACK_SCRIPT}" ]]; then
  echo "[!] Missing or non-executable Wayback script: ${WAYBACK_SCRIPT}" >&2
  exit 1
fi

if [[ -n "${OUTPUT_DIR}" ]]; then
  TARGET_ROOT="$(expand_path "${OUTPUT_DIR}")"
  TARGET_ROOT="$(make_absolute_path "${TARGET_ROOT}")"
  if [[ "${TARGET_ROOT}" != "/" ]]; then
    TARGET_ROOT="${TARGET_ROOT%/}"
  fi
  if [[ -z "${TARGET_ROOT}" ]]; then
    echo "[!] Invalid --output-dir value: ${OUTPUT_DIR}" >&2
    exit 1
  fi
else
  TARGET_ROOT="${HOME}/targets/${DOMAIN}"
fi

echo "${GREEN}[i]${RESET} Preflight OK: all required tools are installed."
echo "${GREEN}[i]${RESET} Target input: ${DOMAIN_INPUT}"
echo "${GREEN}[i]${RESET} Normalized domain: ${DOMAIN}"
echo "${GREEN}[i]${RESET} JS mode: ${JS_DOWNLOAD_MODE} (max per host: ${MAX_JS_PER_HOST}, skip download: ${SKIP_JS_DOWNLOAD})"
echo "${GREEN}[i]${RESET} Timeouts (s): wayback_cdx=${WAYBACK_CDX_TIMEOUT}, wayback_script=${WAYBACK_SCRIPT_TIMEOUT}, gau=${GAU_TIMEOUT}, katana=${KATANA_TIMEOUT}"

step() {
  printf "\n%s==>%s %s\n" "$BOLD$CYAN" "$RESET" "$1"
}

step "Create target directory: ${TARGET_ROOT}"
mkdir -p "${TARGET_ROOT}"
cd "${TARGET_ROOT}"
TARGET_ROOT="$(pwd -P)"

step "Create folder structure"
mkdir -p subs urls alive nuclei_results js js/Output burp-to

step "Run subfinder"
subfinder -d "${DOMAIN}" -silent -o subs/subfinder.txt

step "Run assetfinder"
assetfinder --subs-only "${DOMAIN}" > subs/assetfinder.txt

step "Run amass (passive)"
if ! timeout 300 amass enum -passive -d "${DOMAIN}" -o subs/amass_passive.txt; then
  echo "[!] amass failed or timed out; continuing with other sources." >&2
  : > subs/amass_passive.txt
fi

step "Collect from crt.sh"
CRT_TMP="$(mktemp)"
if curl -fsSL --retry 2 --retry-delay 2 "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "${CRT_TMP}"; then
  if jq -e . "${CRT_TMP}" >/dev/null 2>&1; then
    jq -r '.[].name_value' "${CRT_TMP}" | sed 's/\r//g' | sed 's/^\*\.//' | sed '/^$/d' | sort -u > subs/crtsh.txt
  else
    echo "[!] crt.sh returned non-JSON response; continuing without crt.sh data." >&2
    : > subs/crtsh.txt
  fi
else
  echo "[!] crt.sh request failed; continuing without crt.sh data." >&2
  : > subs/crtsh.txt
fi
rm -f "${CRT_TMP}"

step "Collect hosts from Wayback CDX"
WAYBACK_CDX_STATUS=0
timeout "${WAYBACK_CDX_TIMEOUT}" bash -o pipefail -c "curl -fsS --connect-timeout 10 --max-time 45 \"http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey\" | sed 's_https*://__' | cut -d'/' -f1 | sort -u > subs/wayback.txt" || WAYBACK_CDX_STATUS=$?
if [[ ${WAYBACK_CDX_STATUS} -ne 0 ]]; then
  if [[ ${WAYBACK_CDX_STATUS} -eq 124 ]]; then
    echo "[!] Wayback CDX host query timed out after ${WAYBACK_CDX_TIMEOUT}s; trying wayback.sh fallback." >&2
  else
    echo "[!] Wayback CDX host query failed (status ${WAYBACK_CDX_STATUS}); trying wayback.sh fallback." >&2
  fi
fi

if [[ ! -s subs/wayback.txt ]] && [[ -x "${WAYBACK_SCRIPT}" ]]; then
  WAYBACK_SCRIPT_HOST_STATUS=0
  timeout "${WAYBACK_SCRIPT_TIMEOUT}" "${WAYBACK_SCRIPT}" "${DOMAIN}" -s 2>/dev/null \
    | grep -E '^https?://' \
    | sed 's_https*://__' \
    | cut -d'/' -f1 \
    | sort -u > subs/wayback.txt || WAYBACK_SCRIPT_HOST_STATUS=$?
  if [[ ${WAYBACK_SCRIPT_HOST_STATUS} -ne 0 ]]; then
    if [[ ${WAYBACK_SCRIPT_HOST_STATUS} -eq 124 ]]; then
      echo "[!] wayback.sh host extraction timed out after ${WAYBACK_SCRIPT_TIMEOUT}s; continuing." >&2
    else
      echo "[!] wayback.sh host extraction failed (status ${WAYBACK_SCRIPT_HOST_STATUS}); continuing." >&2
    fi
  fi
fi

if [[ ! -s subs/wayback.txt ]]; then
  echo "[!] Wayback host extraction failed or returned empty output; continuing." >&2
  : > subs/wayback.txt
fi
echo "[i] Wayback hosts collected: $(wc -l < subs/wayback.txt | tr -d ' ')"

step "Merge subdomains"
cat subs/*.txt | sort -u > subs/all_subs.txt

step "Probe live subdomains"
cat subs/all_subs.txt \
  | httpx -ports 80,443,8080,8443 -title -status-code -silent \
  | tee alive/live-subs.txt

step "Extract 200/301/302/403 targets"
sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' alive/live-subs.txt \
  | grep -E '\[(200|301|302|403)\]' > alive/live-subs-200-301-302-403.txt || true

step "Normalize live target list"
awk '{print $1}' alive/live-subs-200-301-302-403.txt > alive/live-subs-200-301-302-403.urls
mv alive/live-subs-200-301-302-403.urls alive/live-subs-200-301-302-403.txt

step "Build URL collection targets (200/301/302 only)"
sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' alive/live-subs.txt \
  | grep -E '\[(200|301|302)\]' > alive/live-subs-url-collect.txt || true
awk '{print $1}' alive/live-subs-url-collect.txt > alive/live-subs-url-collect.urls
mv alive/live-subs-url-collect.urls alive/live-subs-url-collect.txt

# gau performs better on bare hostnames than URL+port strings.
awk '{u=$1; gsub(/^https?:\/\//, "", u); gsub(/:[0-9]+$/, "", u); print u}' alive/live-subs-url-collect.txt \
  | sort -u > alive/gau-input-hosts.txt

step "Extract 404 targets"
sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' alive/live-subs.txt \
  | grep -E '\[404\]' > alive/live-subs-404.txt || true

step "Collect URLs from Wayback script"
if [[ -x "${WAYBACK_SCRIPT}" ]]; then
  WAYBACK_URL_STATUS=0
  timeout "${WAYBACK_SCRIPT_TIMEOUT}" "${WAYBACK_SCRIPT}" "${DOMAIN}" -s 2>/dev/null \
    | grep -E '^https?://' \
    | sort -u \
    | tee urls/wayback.txt || WAYBACK_URL_STATUS=$?
  if [[ ${WAYBACK_URL_STATUS} -ne 0 ]]; then
    if [[ ${WAYBACK_URL_STATUS} -eq 124 ]]; then
      echo "[!] wayback.sh URL collection timed out after ${WAYBACK_SCRIPT_TIMEOUT}s; continuing with partial data." >&2
    else
      echo "[!] wayback.sh URL collection failed (status ${WAYBACK_URL_STATUS}); continuing." >&2
    fi
  fi

  if [[ ! -s urls/wayback.txt ]]; then
    : > urls/wayback.txt
  fi
else
  echo "[!] wayback.sh not executable at ${WAYBACK_SCRIPT}; continuing without Wayback URLs." >&2
  : > urls/wayback.txt
fi
echo "[i] URLs from wayback.sh: $(wc -l < urls/wayback.txt | tr -d ' ')"

step "Collect URLs with gau"
GAU_STATUS=0
: > urls/gau.raw
if [[ -s alive/gau-input-hosts.txt ]]; then
  timeout "${GAU_TIMEOUT}" gau --subs --threads 50 < alive/gau-input-hosts.txt > urls/gau.raw || GAU_STATUS=$?
else
  echo "[i] No gau input hosts found; skipping gau."
fi
if [[ ${GAU_STATUS} -ne 0 ]]; then
  if [[ ${GAU_STATUS} -eq 124 ]]; then
    echo "[!] gau timed out after ${GAU_TIMEOUT}s; continuing with partial/empty output." >&2
  else
    echo "[!] gau failed (status ${GAU_STATUS}); continuing." >&2
  fi
fi
grep -E '^https?://' urls/gau.raw | sort -u > urls/gau.txt || true
if [[ ! -s urls/gau.txt ]]; then
  : > urls/gau.txt
fi
echo "[i] URLs from gau: $(wc -l < urls/gau.txt | tr -d ' ')"

step "Collect URLs with katana"
KATANA_STATUS=0
: > urls/katana.raw
if [[ -s alive/live-subs-url-collect.txt ]]; then
  timeout "${KATANA_TIMEOUT}" katana -silent -jc -d 3 -c 5 -p 5 < alive/live-subs-url-collect.txt > urls/katana.raw || KATANA_STATUS=$?
else
  echo "[i] No katana input targets found; skipping katana."
fi
if [[ ${KATANA_STATUS} -ne 0 ]]; then
  if [[ ${KATANA_STATUS} -eq 124 ]]; then
    echo "[!] katana timed out after ${KATANA_TIMEOUT}s; continuing with partial/empty output." >&2
  else
    echo "[!] katana failed (status ${KATANA_STATUS}); continuing." >&2
  fi
fi
grep -E '^https?://' urls/katana.raw | sort -u > urls/katana_urls.txt || true
if [[ ! -s urls/katana_urls.txt ]]; then
  : > urls/katana_urls.txt
fi
echo "[i] URLs from katana: $(wc -l < urls/katana_urls.txt | tr -d ' ')"

step "Merge URL corpus"
cat urls/*.txt | sort -u | tee urls/all-urls.txt

step "Filter interesting URLs"
cat urls/all-urls.txt \
  | grep -Ei 'login|register|signup|account|user|profile|applicant|appointment|reschedule|payment|pay|invoice|verify|verification|photo|upload|document|passport|visa|api|auth|token' \
  | tee urls/interesting.txt || true

step "Extract parameterized URLs"
cat urls/all-urls.txt | grep '=' | tee urls/params.txt || true

step "Extract API-like URLs"
cat urls/all-urls.txt | grep -Ei '/api/|graphql|swagger|openapi|v1|v2|rest' | tee urls/api.txt || true

step "Extract JavaScript URLs"
awk -F'?' '$1 ~ /\.js$/ {print $0}' urls/all-urls.txt | sort -u > js/js-urls.txt || true

step "Filter JavaScript URLs for hunting focus"
JS_DOWNLOAD_MODE="${JS_DOWNLOAD_MODE:-important}"
MAX_JS_PER_HOST="${MAX_JS_PER_HOST:-30}"
JS_ALL_URLS_FILE="js/js-urls.txt"
JS_IMPORTANT_URLS_FILE="js/js-urls-important.txt"

if [[ "${JS_DOWNLOAD_MODE}" != "important" && "${JS_DOWNLOAD_MODE}" != "all" ]]; then
  echo "[!] Unsupported JS_DOWNLOAD_MODE=${JS_DOWNLOAD_MODE}; using important." >&2
  JS_DOWNLOAD_MODE="important"
fi

if [[ -s "${JS_ALL_URLS_FILE}" ]]; then
  if [[ "${JS_DOWNLOAD_MODE}" == "all" ]]; then
    cp "${JS_ALL_URLS_FILE}" "${JS_IMPORTANT_URLS_FILE}"
  else
    awk -F/ '
      BEGIN { IGNORECASE=1 }
      {
        url=$0
        host=$3
        path=""
        for (i=4; i<=NF; i++) {
          if (i>4) path=path"/"
          path=path $i
        }
        sub(/\?.*$/, "", path)
        path_l=tolower(path)

        n=split(path_l, parts, "/")
        file=parts[n]

        # Skip obvious locale-only bundles: af.js, en.js, en-gb.js, zh-hans.js
        if (file ~ /^[a-z]{2}(-[a-z0-9]{2,8})?\.js$/) next

        # Skip common tracking scripts.
        if (file ~ /^(gtm|gtag|analytics|clarity|hotjar|fbevents|recaptcha|captcha)\.js$/) next

        important=0
        if (file ~ /^(main|runtime|polyfills|app|bundle|vendor|webpack|common)([-._].*)?\.js$/) important=1
        if (file ~ /^([0-9]{1,4}|chunk)([-._].*)?\.js$/) important=1
        if (path_l ~ /(api|auth|login|register|signup|account|user|profile|applicant|appointment|resched|booking|payment|invoice|passport|visa|document|upload|photo|admin|token|session|oauth|sso|otp|verify|graphql|socket|websocket)/) important=1

        if (important) print url
      }
    ' "${JS_ALL_URLS_FILE}" | sort -u > "${JS_IMPORTANT_URLS_FILE}.raw"

    if [[ "${MAX_JS_PER_HOST}" =~ ^[0-9]+$ ]] && [[ "${MAX_JS_PER_HOST}" -gt 0 ]]; then
      awk -F/ -v max="${MAX_JS_PER_HOST}" '{host=$3; if (++count[host] <= max) print $0}' "${JS_IMPORTANT_URLS_FILE}.raw" > "${JS_IMPORTANT_URLS_FILE}"
    else
      cp "${JS_IMPORTANT_URLS_FILE}.raw" "${JS_IMPORTANT_URLS_FILE}"
    fi
    rm -f "${JS_IMPORTANT_URLS_FILE}.raw"

    if [[ ! -s "${JS_IMPORTANT_URLS_FILE}" ]]; then
      echo "[i] Important JS filter returned empty; falling back to all JS URLs."
      cp "${JS_ALL_URLS_FILE}" "${JS_IMPORTANT_URLS_FILE}"
    fi
  fi

  echo "[i] JS URLs total: $(wc -l < "${JS_ALL_URLS_FILE}" | tr -d ' ')"
  echo "[i] JS URLs selected (${JS_DOWNLOAD_MODE} mode): $(wc -l < "${JS_IMPORTANT_URLS_FILE}" | tr -d ' ')"
else
  : > "${JS_IMPORTANT_URLS_FILE}"
fi

step "Write AI handoff guide"
cat > "NEXT_STEPS_AI.md" <<EOF2
Use the prompts below with AI after this recon finishes (up to the wget step).

Prompt 1:
Analyze this js folder (JavaScript files) from a production web application.

Your job is to perform a structured security-focused triage, not just a generic summary.

Phase 1:

1. Build an inventory of all JS files.
2. Identify likely app code vs vendor/framework/minified library code.
3. Extract and deduplicate:
   - API endpoints
   - GraphQL endpoints, queries, and mutations
   - WebSocket endpoints
   - Internal URLs, hostnames, IPs, S3/bucket references
   - Tokens, keys, secrets, credentials, or suspicious constants
4. Identify files containing likely security-relevant logic:
   - auth
   - role checks
   - admin features
   - payment
   - booking
   - applicant/profile handling
   - upload/document/photo/facial verification flows
5. Flag files with comments, debug code, feature flags, or disabled security checks.

Phase 2:
For the most interesting files, explain:

- why the file matters
- what sensitive functionality it contains
- what endpoints and parameters appear important
- whether access control appears client-side only
- whether IDs like userId, applicantId, appointmentId, slotId, paymentId, profileId are present
- whether there are hidden or undocumented routes not obvious from the UI

Output files in Output folder in js folder:

1. inventory.md
2. interesting-files.txt
3. endpoints.txt
4. graphql.txt
5. websocket.txt
6. internal-assets.txt
7. secrets-findings.md
8. suspicious-client-side-controls.md
9. final-summary.md

Be concrete. Quote exact file paths and code snippets only when needed. Deduplicate aggressively. Prioritize findings that could help manual testing for IDOR, auth bypass, appointment logic abuse, reschedule tampering, payment tampering, and hidden admin functionality.

Prompt 2:
Using the previous analysis, create a manual testing shortlist for Burp Suite.
For each high-value endpoint or JS-discovered function, provide:
- endpoint/path
- likely method
- key parameters/IDs
- why it is suspicious
- specific manual tests to try for IDOR, auth bypass, workflow bypass, reschedule tampering, photo tampering, payment tampering, or hidden admin access

make it in file ${TARGET_ROOT}/burp-to/burp_manual_testing_shortlist.csv

Prompt 3:
make me endpoints from this file burp-to/burp_manual_testing_shortlist.csv on those hosts tp test on burp I want like a request copy past
Start with these hosts first (highest value from the JS analysis):

---THE HOSTS HERE

make it in this new folder ${TARGET_ROOT}/burp-to
EOF2

step "Download JavaScript files"
if [[ "${SKIP_JS_DOWNLOAD:-0}" == "1" ]]; then
  echo "[i] SKIP_JS_DOWNLOAD=1 set; skipping wget stage and keeping AI handoff file."
elif [[ -s "${JS_IMPORTANT_URLS_FILE:-js/js-urls-important.txt}" ]]; then
  JS_DOWNLOAD_SOURCE_FILE="${JS_IMPORTANT_URLS_FILE:-js/js-urls-important.txt}"
  JS_HOSTS_FILE="js/js-hosts.txt"
  JS_RESPONSIVE_HOSTS_FILE="js/js-responsive-hosts.txt"
  JS_DOWNLOAD_LIST_FILE="js/js-urls-download.txt"

  step "Probe JS hosts to avoid dead targets"
  awk -F/ 'NF > 3 {print $3}' "${JS_DOWNLOAD_SOURCE_FILE}" | sort -u > "${JS_HOSTS_FILE}"
  : > "${JS_RESPONSIVE_HOSTS_FILE}"

  while IFS= read -r host; do
    [[ -z "${host}" ]] && continue
    if timeout 10 curl -kIsS --connect-timeout 4 --max-time 8 "https://${host}/" >/dev/null 2>&1 \
      || timeout 10 curl -kIsS --connect-timeout 4 --max-time 8 "http://${host}/" >/dev/null 2>&1; then
      echo "${host}" >> "${JS_RESPONSIVE_HOSTS_FILE}"
    else
      echo "[i] Skipping slow/unreachable JS host: ${host}"
    fi
  done < "${JS_HOSTS_FILE}"

  if [[ -s "${JS_RESPONSIVE_HOSTS_FILE}" ]]; then
    awk -F/ 'NR==FNR {ok[$1]=1; next} ok[$3] {print $0}' "${JS_RESPONSIVE_HOSTS_FILE}" "${JS_DOWNLOAD_SOURCE_FILE}" \
      | sort -u > "${JS_DOWNLOAD_LIST_FILE}"
  else
    : > "${JS_DOWNLOAD_LIST_FILE}"
  fi

  TOTAL_JS_URLS=$(wc -l < "${JS_DOWNLOAD_SOURCE_FILE}" | tr -d ' ')
  QUEUED_JS_URLS=$(wc -l < "${JS_DOWNLOAD_LIST_FILE}" | tr -d ' ')
  echo "[i] JS URLs queued for wget (${JS_DOWNLOAD_MODE} mode): ${TOTAL_JS_URLS}; after host probe: ${QUEUED_JS_URLS}"

  if [[ -s "${JS_DOWNLOAD_LIST_FILE}" ]]; then
    JS_OK=0
    JS_TIMEOUT=0
    JS_FAIL=0

    while IFS= read -r js_url; do
      [[ -z "${js_url}" ]] && continue
      JS_WGET_STATUS=0
      timeout 40 wget "${js_url}" -P js \
        --content-disposition \
        --trust-server-names \
        --tries=1 \
        --dns-timeout=5 \
        --connect-timeout=5 \
        --read-timeout=15 \
        --timeout=20 \
        --retry-connrefused \
        --no-verbose \
        -e background=off || JS_WGET_STATUS=$?

      if [[ ${JS_WGET_STATUS} -eq 0 ]]; then
        JS_OK=$((JS_OK + 1))
      elif [[ ${JS_WGET_STATUS} -eq 124 ]]; then
        JS_TIMEOUT=$((JS_TIMEOUT + 1))
      else
        JS_FAIL=$((JS_FAIL + 1))
      fi
    done < "${JS_DOWNLOAD_LIST_FILE}"

    echo "[i] JS download summary: success=${JS_OK}, timeout=${JS_TIMEOUT}, failed=${JS_FAIL}"
  else
    echo "[i] No responsive JS hosts found; skipping wget."
  fi
else
  echo "[i] No JS URLs selected for download; skipping wget."
fi

step "Done"
echo "${GREEN}[+]${RESET} Recon automation completed for ${DOMAIN}"
echo "${GREEN}[+]${RESET} Output folder: ${TARGET_ROOT}"
