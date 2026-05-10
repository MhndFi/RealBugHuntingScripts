#!/usr/bin/env bash
# ==============================================================================
# MFrecon.sh — bug bounty recon + active scanning pipeline (macOS Apple Silicon)
# ==============================================================================
#
# Pipeline stages (sequential):
#   1. Subdomain enum  (subfinder, assetfinder, amass, crt.sh, wayback CDX)
#   2. Live host probe (httpx)
#   3. URL collection  (wayback, gau, katana)
#   4. URL filtering   (interesting / params / api / js)
#   5. Param mining    (paramspider on apex, arjun on alive hosts)
#   6. Pattern triage  (gf: sqli/xss/ssrf/lfi/redirect/rce/ssti/idor)
#   7. JS download     (wget on filtered JS URLs)
#   8. Secret scanning (trufflehog + gitleaks on downloaded JS)
#   9. Content fuzzing (ffuf on alive hosts, raft-medium-directories)
#  10. XSS scanning    (dalfox on gf/xss.txt)
#  11. Nuclei standard (CVEs/exposures/misconfigs on alive hosts)
#  12. Nuclei DAST     (sqli/xss/ssrf/lfi/redirect/ssti/rce on params.txt)
#  13. Notify summary  (Discord/Slack via notify)
#  14. AI handoff      (NEXT_STEPS_AI.md for downstream JS analysis)
#
# Auto-detects bash 5 (uses ${VAR,,}) vs falls back to tr lowercase.
# Auto-detects GNU coreutils (gtimeout) vs BSD timeout.
# ==============================================================================

set -uo pipefail
# NOTE: -e intentionally disabled — bug bounty scripts have many tools that
# legitimately fail (timeouts, no findings, WAFs); we handle errors per-stage.

# ------------------------------------------------------------------------------
# 0.  Bash version detection + GNU userland shim
# ------------------------------------------------------------------------------
BASH_MAJOR="${BASH_VERSINFO[0]:-3}"
HAS_BASH4=0
[[ "${BASH_MAJOR}" -ge 4 ]] && HAS_BASH4=1

# Prefer Homebrew bash 5 if invoked via /usr/bin/env bash and a newer one exists
if [[ ${HAS_BASH4} -eq 0 ]] && [[ -x /opt/homebrew/bin/bash ]]; then
  echo "[i] Detected bash 3.2; re-exec'ing under /opt/homebrew/bin/bash" >&2
  exec /opt/homebrew/bin/bash "$0" "$@"
fi

# Add Homebrew GNU userland to PATH if present (gnubin paths)
if command -v brew >/dev/null 2>&1; then
  for pkg in coreutils gnu-sed grep findutils gawk; do
    GNUBIN="$(brew --prefix "${pkg}" 2>/dev/null)/libexec/gnubin"
    [[ -d "${GNUBIN}" ]] && PATH="${GNUBIN}:${PATH}"
  done
  export PATH
fi

# Add Go bin + pipx bin to PATH (idempotent)
[[ -d "${HOME}/go/bin"     ]] && export PATH="${HOME}/go/bin:${PATH}"
[[ -d "${HOME}/.local/bin" ]] && export PATH="${HOME}/.local/bin:${PATH}"
[[ -d /opt/homebrew/bin    ]] && export PATH="/opt/homebrew/bin:${PATH}"
[[ -d /opt/gobin           ]] && export PATH="/opt/gobin:${PATH}"

# Resolve a portable timeout
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
else
  echo "[!] No timeout binary found. Install: brew install coreutils" >&2
  exit 1
fi

# Raise file-descriptor limit for httpx/nuclei/ffuf fanout (M4 Pro headroom)
ulimit -n 12288 2>/dev/null || ulimit -n 8192 2>/dev/null || true

# ------------------------------------------------------------------------------
# 1.  Styling / banner
# ------------------------------------------------------------------------------
if [[ -t 1 ]]; then
  BOLD=$'\033[1m';  CYAN=$'\033[36m'; GREEN=$'\033[32m'
  YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
else
  BOLD="" CYAN="" GREEN="" YELLOW="" RED="" RESET=""
fi

print_banner() {
  cat <<'BANNER'
 __  __ _   _ _   _ ____  _____ ___
|  \/  | | | | \ | |  _ \|  ___|_ _|
| |\/| | |_| |  \| | | | | |_   | |
| |  | |  _  | |\  | |_| |  _|  | |
|_|  |_|_| |_|_| \_|____/|_|   |___|
BANNER
  printf "%s%sMhndFi Recon Toolkit v2 — macOS Apple Silicon%s\n" "${BOLD}" "${CYAN}" "${RESET}"
}

step()    { printf "\n%s==>%s %s\n" "${BOLD}${CYAN}" "${RESET}" "$1"; }
info()    { printf "%s[i]%s %s\n"   "${GREEN}"        "${RESET}" "$1"; }
warn()    { printf "%s[!]%s %s\n"   "${YELLOW}"       "${RESET}" "$1" >&2; }
err()     { printf "%s[X]%s %s\n"   "${RED}"          "${RESET}" "$1" >&2; }

# ------------------------------------------------------------------------------
# 2.  Usage
# ------------------------------------------------------------------------------
usage() {
  cat <<'USAGE'
Usage:
  MFrecon.sh [options] <domain>

Recon + active scanning pipeline for a single root domain.

Options:
  -h, --help                           Show this help.
  -o, --output-dir <path>              Custom output dir (default: ~/targets/<domain>).
  --js-mode <important|all>            JS download filter mode. Default: important.
  --max-js-per-host <n>                Cap selected JS URLs per host. Default: 30.
  --skip-js-download                   Skip wget JS download stage.
  --skip-nuclei                        Skip both nuclei passes.
  --skip-dast                          Skip nuclei DAST pass (run standard only).
  --skip-dalfox                        Skip dalfox XSS scanning.
  --skip-ffuf                          Skip ffuf content discovery.
  --skip-secrets                       Skip trufflehog + gitleaks.
  --skip-paramspider                   Skip paramspider/arjun param mining.
  --skip-notify                        Disable Discord/Slack notify hooks.
  --notify-id <name>                   Override notify provider id (default: default).
  --nuclei-fa <low|medium|high>        Nuclei DAST aggression. Default: medium.
  --nuclei-rl <n>                      Nuclei standard rate-limit. Default: 150.
  --nuclei-dast-rl <n>                 Nuclei DAST rate-limit. Default: 50.
  --ffuf-wordlist <path>               Override ffuf wordlist.
  --xss-callback <url>                 dalfox blind XSS callback (-b).
  --max-ffuf-hosts <n>                 Cap ffuf to top-N alive hosts. Default: 20.
  --wayback-cdx-timeout <sec>          Default: 90.
  --wayback-script-timeout <sec>       Default: 180.
  --gau-timeout <sec>                  Default: 180.
  --katana-timeout <sec>               Default: 300.

Environment overrides (same names, uppercase):
  OUTPUT_DIR, JS_DOWNLOAD_MODE, MAX_JS_PER_HOST, SKIP_*, NUCLEI_FA, NUCLEI_RL,
  NUCLEI_DAST_RL, FFUF_WORDLIST, XSS_CALLBACK, MAX_FFUF_HOSTS, NOTIFY_ID

Examples:
  MFrecon.sh example.com
  MFrecon.sh -o ~/recon/acme acme.com
  MFrecon.sh --skip-nuclei --skip-ffuf example.com
  MFrecon.sh --xss-callback https://yourcb.xss.ht example.com
USAGE
}

# ------------------------------------------------------------------------------
# 3.  Path helpers
# ------------------------------------------------------------------------------
START_PWD="$(pwd)"

expand_path() {
  local path="$1"
  case "${path}" in
    "~")     printf '%s\n' "${HOME}" ;;
    "~/"*)   printf '%s/%s\n' "${HOME}" "${path#"~/"}" ;;
    *)       printf '%s\n' "${path}" ;;
  esac
}
make_absolute_path() {
  local path="$1"
  if [[ "${path}" == /* ]]; then printf '%s\n' "${path}"
  else printf '%s/%s\n' "${START_PWD}" "${path}"
  fi
}

# Lowercase helper (bash 4 vs bash 3 portable)
to_lower() {
  if [[ ${HAS_BASH4} -eq 1 ]]; then
    local s="$1"; printf '%s' "${s,,}"
  else
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
  fi
}

# ------------------------------------------------------------------------------
# 4.  Defaults + arg parsing
# ------------------------------------------------------------------------------
OUTPUT_DIR="${OUTPUT_DIR:-}"
JS_DOWNLOAD_MODE="${JS_DOWNLOAD_MODE:-important}"
MAX_JS_PER_HOST="${MAX_JS_PER_HOST:-30}"
SKIP_JS_DOWNLOAD="${SKIP_JS_DOWNLOAD:-0}"
SKIP_NUCLEI="${SKIP_NUCLEI:-0}"
SKIP_DAST="${SKIP_DAST:-0}"
SKIP_DALFOX="${SKIP_DALFOX:-0}"
SKIP_FFUF="${SKIP_FFUF:-0}"
SKIP_SECRETS="${SKIP_SECRETS:-0}"
SKIP_PARAMSPIDER="${SKIP_PARAMSPIDER:-0}"
SKIP_NOTIFY="${SKIP_NOTIFY:-0}"
NOTIFY_ID="${NOTIFY_ID:-default}"
NUCLEI_FA="${NUCLEI_FA:-medium}"
NUCLEI_RL="${NUCLEI_RL:-150}"
NUCLEI_DAST_RL="${NUCLEI_DAST_RL:-50}"
FFUF_WORDLIST="${FFUF_WORDLIST:-}"
XSS_CALLBACK="${XSS_CALLBACK:-}"
MAX_FFUF_HOSTS="${MAX_FFUF_HOSTS:-20}"
WAYBACK_CDX_TIMEOUT="${WAYBACK_CDX_TIMEOUT:-90}"
WAYBACK_SCRIPT_TIMEOUT="${WAYBACK_SCRIPT_TIMEOUT:-180}"
GAU_TIMEOUT="${GAU_TIMEOUT:-180}"
KATANA_TIMEOUT="${KATANA_TIMEOUT:-300}"

DOMAIN_INPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    -o|--output-dir)              OUTPUT_DIR="$2"; shift 2 ;;
    --js-mode)                    JS_DOWNLOAD_MODE="$2"; shift 2 ;;
    --max-js-per-host)            MAX_JS_PER_HOST="$2"; shift 2 ;;
    --skip-js-download)           SKIP_JS_DOWNLOAD=1; shift ;;
    --skip-nuclei)                SKIP_NUCLEI=1; shift ;;
    --skip-dast)                  SKIP_DAST=1; shift ;;
    --skip-dalfox)                SKIP_DALFOX=1; shift ;;
    --skip-ffuf)                  SKIP_FFUF=1; shift ;;
    --skip-secrets)               SKIP_SECRETS=1; shift ;;
    --skip-paramspider)           SKIP_PARAMSPIDER=1; shift ;;
    --skip-notify)                SKIP_NOTIFY=1; shift ;;
    --notify-id)                  NOTIFY_ID="$2"; shift 2 ;;
    --nuclei-fa)                  NUCLEI_FA="$2"; shift 2 ;;
    --nuclei-rl)                  NUCLEI_RL="$2"; shift 2 ;;
    --nuclei-dast-rl)             NUCLEI_DAST_RL="$2"; shift 2 ;;
    --ffuf-wordlist)              FFUF_WORDLIST="$2"; shift 2 ;;
    --xss-callback)               XSS_CALLBACK="$2"; shift 2 ;;
    --max-ffuf-hosts)             MAX_FFUF_HOSTS="$2"; shift 2 ;;
    --wayback-cdx-timeout)        WAYBACK_CDX_TIMEOUT="$2"; shift 2 ;;
    --wayback-script-timeout)     WAYBACK_SCRIPT_TIMEOUT="$2"; shift 2 ;;
    --gau-timeout)                GAU_TIMEOUT="$2"; shift 2 ;;
    --katana-timeout)             KATANA_TIMEOUT="$2"; shift 2 ;;
    --) shift; break ;;
    -*) err "Unknown option: $1"; usage; exit 1 ;;
    *)
      if [[ -z "${DOMAIN_INPUT}" ]]; then DOMAIN_INPUT="$1"
      else err "Unexpected extra argument: $1"; usage; exit 1
      fi
      shift ;;
  esac
done

[[ -z "${DOMAIN_INPUT}" ]] && { usage; exit 1; }

# Validate enums
if [[ "${JS_DOWNLOAD_MODE}" != "important" && "${JS_DOWNLOAD_MODE}" != "all" ]]; then
  err "Invalid --js-mode: ${JS_DOWNLOAD_MODE}"; exit 1
fi
if [[ "${NUCLEI_FA}" != "low" && "${NUCLEI_FA}" != "medium" && "${NUCLEI_FA}" != "high" ]]; then
  err "Invalid --nuclei-fa: ${NUCLEI_FA}"; exit 1
fi
for NUM_OPT in MAX_JS_PER_HOST NUCLEI_RL NUCLEI_DAST_RL MAX_FFUF_HOSTS \
               WAYBACK_CDX_TIMEOUT WAYBACK_SCRIPT_TIMEOUT GAU_TIMEOUT KATANA_TIMEOUT; do
  if ! [[ "${!NUM_OPT}" =~ ^[0-9]+$ ]]; then
    err "Invalid numeric value for ${NUM_OPT}: ${!NUM_OPT}"; exit 1
  fi
done

# Normalize domain
DOMAIN="${DOMAIN_INPUT#http://}"
DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"
DOMAIN="${DOMAIN%%:*}"
DOMAIN="${DOMAIN%.}"
DOMAIN="$(to_lower "${DOMAIN}")"
[[ "${DOMAIN}" == \*.* ]] && DOMAIN="${DOMAIN#*.}"
[[ "${DOMAIN}" == www.* ]] && DOMAIN="${DOMAIN#www.}"

if [[ -z "${DOMAIN}" ]]; then err "Invalid domain input: ${DOMAIN_INPUT}"; exit 1; fi
if [[ "${DOMAIN}" =~ [^a-z0-9.-] ]]; then err "Domain contains unsupported characters: ${DOMAIN}"; exit 1; fi

trap 'printf "\n[!] Interrupted by user.\n" >&2; exit 130' INT

print_banner

# ------------------------------------------------------------------------------
# 5.  Tool preflight
# ------------------------------------------------------------------------------
REQUIRED_CORE=( subfinder assetfinder amass curl jq httpx gau katana wget
                "${TIMEOUT_BIN}" sed awk grep sort cut tee mktemp xargs )

OPTIONAL_TOOLS=()
[[ "${SKIP_NUCLEI}" == "0"      ]] && OPTIONAL_TOOLS+=( nuclei qsreplace )
[[ "${SKIP_DALFOX}" == "0"      ]] && OPTIONAL_TOOLS+=( dalfox )
[[ "${SKIP_FFUF}"   == "0"      ]] && OPTIONAL_TOOLS+=( ffuf )
[[ "${SKIP_SECRETS}" == "0"     ]] && OPTIONAL_TOOLS+=( trufflehog gitleaks )
[[ "${SKIP_PARAMSPIDER}" == "0" ]] && OPTIONAL_TOOLS+=( paramspider arjun )
[[ "${SKIP_NOTIFY}"  == "0"     ]] && OPTIONAL_TOOLS+=( notify )
OPTIONAL_TOOLS+=( gf )

MISSING_CORE=()
for t in "${REQUIRED_CORE[@]}"; do
  command -v "${t}" >/dev/null 2>&1 || MISSING_CORE+=("${t}")
done

if [[ ${#MISSING_CORE[@]} -gt 0 ]]; then
  err "Missing required tools: ${MISSING_CORE[*]}"
  err "Run: ./setup-toolchain.sh"
  exit 1
fi

MISSING_OPTIONAL=()
for t in "${OPTIONAL_TOOLS[@]}"; do
  command -v "${t}" >/dev/null 2>&1 || MISSING_OPTIONAL+=("${t}")
done
if [[ ${#MISSING_OPTIONAL[@]} -gt 0 ]]; then
  warn "Missing optional tools (matching stages will be skipped): ${MISSING_OPTIONAL[*]}"
fi
declare -A HAS_TOOL=()
for t in "${OPTIONAL_TOOLS[@]}"; do
  if command -v "${t}" >/dev/null 2>&1; then HAS_TOOL["${t}"]=1
  else HAS_TOOL["${t}"]=0
  fi
done

# Resolve external scripts
WAYBACK_SCRIPT="${HOME}/Tools/wayback.sh"
[[ ! -x "${WAYBACK_SCRIPT}" ]] && WAYBACK_SCRIPT=""

# Resolve ffuf wordlist
if [[ "${SKIP_FFUF}" == "0" ]] && [[ -z "${FFUF_WORDLIST}" ]]; then
  for cand in \
      /opt/homebrew/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
      /usr/local/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
      /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
      /opt/homebrew/share/seclists/Discovery/Web-Content/common.txt; do
    [[ -f "${cand}" ]] && FFUF_WORDLIST="${cand}" && break
  done
  if [[ -z "${FFUF_WORDLIST}" ]]; then
    warn "No SecLists wordlist found; ffuf will be skipped."
    SKIP_FFUF=1
  fi
fi

# ------------------------------------------------------------------------------
# 6.  Output directory
# ------------------------------------------------------------------------------
if [[ -n "${OUTPUT_DIR}" ]]; then
  TARGET_ROOT="$(expand_path "${OUTPUT_DIR}")"
  TARGET_ROOT="$(make_absolute_path "${TARGET_ROOT}")"
  TARGET_ROOT="${TARGET_ROOT%/}"
else
  TARGET_ROOT="${HOME}/targets/${DOMAIN}"
fi

mkdir -p "${TARGET_ROOT}"
cd "${TARGET_ROOT}" || { err "Cannot enter ${TARGET_ROOT}"; exit 1; }
TARGET_ROOT="$(pwd -P)"

mkdir -p subs urls alive js js/Output \
         nuclei_results nuclei_results/responses \
         gf params ffuf dalfox secrets burp-to logs

RUN_TS="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="${TARGET_ROOT}/logs/run-${RUN_TS}.log"
TIMING_FILE="${TARGET_ROOT}/logs/stage-timing.csv"
[[ ! -f "${TIMING_FILE}" ]] && echo "stage,start,end,duration_sec,status" > "${TIMING_FILE}"

# ------------------------------------------------------------------------------
# 7.  Notify helper
# ------------------------------------------------------------------------------
ping_notify() {
  local msg="$1"
  [[ "${SKIP_NOTIFY}" == "1" ]] && return 0
  [[ "${HAS_TOOL[notify]:-0}" != "1" ]] && return 0
  echo "[$(date '+%H:%M:%S')] ${DOMAIN} :: ${msg}" \
    | notify -id "${NOTIFY_ID}" -silent 2>/dev/null || true
}

run_stage() {
  # run_stage <name> <command...>
  local name="$1"; shift
  local start end dur status=0
  start="$(date +%s)"
  step "${name}"
  "$@" || status=$?
  end="$(date +%s)"
  dur=$(( end - start ))
  echo "${name},${start},${end},${dur},${status}" >> "${TIMING_FILE}"
  if [[ ${status} -eq 0 ]]; then
    info "${name} completed in ${dur}s"
  else
    warn "${name} exited with status ${status} after ${dur}s (continuing)"
  fi
  return 0
}

info "Target: ${DOMAIN_INPUT}  →  ${DOMAIN}"
info "Output: ${TARGET_ROOT}"
info "Bash: $(bash --version | head -n1)"
info "Timeout: ${TIMEOUT_BIN}"
info "FFUF wordlist: ${FFUF_WORDLIST:-<skipped>}"
info "Run log: ${LOG_FILE}"

ping_notify "🚀 MFrecon started for ${DOMAIN}"

# ==============================================================================
# STAGE 1 — Subdomain enumeration
# ==============================================================================
stage_subdomains() {
  step "Run subfinder"
  subfinder -d "${DOMAIN}" -silent -all -recursive -o subs/subfinder.txt 2>/dev/null \
    || subfinder -d "${DOMAIN}" -silent -o subs/subfinder.txt 2>/dev/null \
    || : > subs/subfinder.txt

  step "Run assetfinder"
  assetfinder --subs-only "${DOMAIN}" > subs/assetfinder.txt 2>/dev/null || true

  step "Run amass (passive)"
  if ! "${TIMEOUT_BIN}" 300 amass enum -passive -d "${DOMAIN}" -o subs/amass.txt 2>/dev/null; then
    warn "amass timed out or failed; continuing."
    : > subs/amass.txt
  fi

  step "Collect from crt.sh"
  local crt_tmp; crt_tmp="$(mktemp)"
  if curl -fsSL --retry 2 --retry-delay 2 \
       "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o "${crt_tmp}" 2>/dev/null \
     && jq -e . "${crt_tmp}" >/dev/null 2>&1; then
    jq -r '.[].name_value' "${crt_tmp}" \
      | sed 's/\r//g' \
      | tr ',' '\n' \
      | sed 's/^\*\.//' \
      | sed '/^$/d' \
      | sort -u > subs/crtsh.txt
  else
    warn "crt.sh failed or returned non-JSON; continuing."
    : > subs/crtsh.txt
  fi
  rm -f "${crt_tmp}"

  step "Collect hosts from Wayback CDX"
  "${TIMEOUT_BIN}" "${WAYBACK_CDX_TIMEOUT}" bash -c "
    curl -fsS --connect-timeout 10 --max-time 45 \
      'http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey' \
      | sed 's_https*://__' | cut -d/ -f1 | sort -u
  " > subs/wayback.txt 2>/dev/null || warn "Wayback CDX query failed."
  [[ ! -s subs/wayback.txt ]] && : > subs/wayback.txt

  if [[ -n "${WAYBACK_SCRIPT}" ]] && [[ ! -s subs/wayback.txt ]]; then
    "${TIMEOUT_BIN}" "${WAYBACK_SCRIPT_TIMEOUT}" "${WAYBACK_SCRIPT}" "${DOMAIN}" -s 2>/dev/null \
      | grep -E '^https?://' | sed 's_https*://__' | cut -d/ -f1 | sort -u \
      > subs/wayback.txt 2>/dev/null || true
  fi

  step "Merge subdomains"
  cat subs/*.txt 2>/dev/null \
    | grep -E "(^|\.)${DOMAIN}\$|^${DOMAIN}\$" \
    | sort -u > subs/all-subs.txt
  local n; n=$(wc -l < subs/all-subs.txt | tr -d ' ')
  info "Total unique subdomains: ${n}"
  ping_notify "📡 Subdomain enum done — ${n} unique subs"
}
run_stage "Stage 1: Subdomain enumeration" stage_subdomains

# ==============================================================================
# STAGE 2 — Live host probe
# ==============================================================================
stage_live_probe() {
  step "Probe live subdomains with httpx"
  if [[ ! -s subs/all-subs.txt ]]; then
    warn "No subdomains to probe."
    : > alive/live-subs.txt
    return 0
  fi

  httpx -l subs/all-subs.txt \
        -ports 80,443,8080,8443,8000,8888 \
        -title -status-code -tech-detect \
        -threads 50 -rate-limit 150 \
        -timeout 10 -retries 1 \
        -silent \
    | tee alive/live-subs.txt

  step "Extract 200/301/302/403 targets"
  sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' alive/live-subs.txt \
    | grep -E '\[(200|301|302|403)\]' > alive/live-subs-200-301-302-403.txt 2>/dev/null || true

  awk '{print $1}' alive/live-subs-200-301-302-403.txt \
    > alive/live-subs-200-301-302-403.urls 2>/dev/null || true
  mv -f alive/live-subs-200-301-302-403.urls alive/live-subs-200-301-302-403.txt 2>/dev/null || true

  step "Build URL collection targets (200/301/302 only)"
  sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' alive/live-subs.txt \
    | grep -E '\[(200|301|302)\]' \
    | awk '{print $1}' > alive/live-subs-url-collect.txt 2>/dev/null || true

  # gau wants bare hostnames (no scheme/port)
  awk '{u=$1; gsub(/^https?:\/\//,"",u); gsub(/:[0-9]+$/,"",u); print u}' \
    alive/live-subs-url-collect.txt | sort -u > alive/gau-input-hosts.txt

  step "Extract 404 targets"
  sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' alive/live-subs.txt \
    | grep -E '\[404\]' > alive/live-subs-404.txt 2>/dev/null || true

  # Build a clean 'just-URLs' file for downstream stages (one URL per line, no annotations)
  awk '{print $1}' alive/live-subs.txt | sort -u > alive/live-subs.urls

  local n; n=$(wc -l < alive/live-subs-200-301-302-403.txt | tr -d ' ')
  info "Live targets (200/301/302/403): ${n}"
  ping_notify "🌐 Live probe done — ${n} responsive hosts"
}
run_stage "Stage 2: Live host probe" stage_live_probe

# ==============================================================================
# STAGE 3 — URL collection
# ==============================================================================
stage_urls() {
  if [[ -n "${WAYBACK_SCRIPT}" ]]; then
    step "Collect URLs from wayback.sh"
    "${TIMEOUT_BIN}" "${WAYBACK_SCRIPT_TIMEOUT}" "${WAYBACK_SCRIPT}" "${DOMAIN}" -s 2>/dev/null \
      | grep -E '^https?://' | sort -u > urls/wayback.txt 2>/dev/null || true
  else
    : > urls/wayback.txt
  fi
  info "URLs from wayback.sh: $(wc -l < urls/wayback.txt | tr -d ' ')"

  step "Collect URLs with gau"
  if [[ -s alive/gau-input-hosts.txt ]]; then
    "${TIMEOUT_BIN}" "${GAU_TIMEOUT}" gau --subs --threads 50 \
      < alive/gau-input-hosts.txt 2>/dev/null \
      | grep -E '^https?://' | sort -u > urls/gau.txt || true
  else
    : > urls/gau.txt
  fi
  info "URLs from gau: $(wc -l < urls/gau.txt | tr -d ' ')"

  step "Collect URLs with katana"
  if [[ -s alive/live-subs-url-collect.txt ]]; then
    "${TIMEOUT_BIN}" "${KATANA_TIMEOUT}" katana \
      -list alive/live-subs-url-collect.txt \
      -silent -jc -d 3 -c 5 -p 5 \
      2>/dev/null \
      | grep -E '^https?://' | sort -u > urls/katana.txt || true
  else
    : > urls/katana.txt
  fi
  info "URLs from katana: $(wc -l < urls/katana.txt | tr -d ' ')"

  step "Merge + dedupe URL corpus"
  if command -v qsreplace >/dev/null 2>&1; then
    cat urls/wayback.txt urls/gau.txt urls/katana.txt 2>/dev/null \
      | qsreplace -a | sort -u > urls/all-urls.txt
  else
    cat urls/wayback.txt urls/gau.txt urls/katana.txt 2>/dev/null \
      | sort -u > urls/all-urls.txt
  fi
  local n; n=$(wc -l < urls/all-urls.txt | tr -d ' ')
  info "Total unique URLs: ${n}"

  step "Filter interesting URLs"
  grep -Ei 'login|register|signup|account|user|profile|applicant|appointment|reschedule|payment|pay|invoice|verify|verification|photo|upload|document|passport|visa|api|auth|token|admin|debug|test|dev|staging' \
    urls/all-urls.txt | sort -u > urls/interesting.txt 2>/dev/null || true

  step "Extract parameterized URLs (for nuclei -dast input)"
  grep -E '\?[a-zA-Z_][^=]*=' urls/all-urls.txt | sort -u > urls/params.txt 2>/dev/null || true
  info "Parameterized URLs: $(wc -l < urls/params.txt | tr -d ' ')"

  step "Extract API-like URLs"
  grep -Ei '/api/|graphql|swagger|openapi|/v1/|/v2/|/v3/|/rest/' urls/all-urls.txt \
    | sort -u > urls/api.txt 2>/dev/null || true

  step "Extract JavaScript URLs"
  awk -F'?' '$1 ~ /\.js$/ {print $0}' urls/all-urls.txt | sort -u > js/js-urls.txt

  ping_notify "🔗 URL collection done — ${n} URLs, $(wc -l < urls/params.txt | tr -d ' ') with params"
}
run_stage "Stage 3: URL collection" stage_urls

# ==============================================================================
# STAGE 4 — Pattern triage with gf
# ==============================================================================
stage_gf() {
  if [[ "${HAS_TOOL[gf]:-0}" != "1" ]]; then
    warn "gf not installed; skipping pattern triage."
    return 0
  fi
  if [[ ! -s urls/all-urls.txt ]]; then
    warn "No URLs to pattern-match; skipping gf."
    return 0
  fi

  for pat in sqli xss ssrf lfi redirect rce ssti idor; do
    if gf -list 2>/dev/null | grep -qx "${pat}"; then
      gf "${pat}" < urls/all-urls.txt 2>/dev/null | sort -u > "gf/${pat}.txt" || true
      info "gf/${pat}.txt: $(wc -l < "gf/${pat}.txt" | tr -d ' ')"
    else
      warn "gf pattern '${pat}' not installed; skipping."
      : > "gf/${pat}.txt"
    fi
  done
  ping_notify "🎯 gf triage — sqli:$(wc -l < gf/sqli.txt|tr -d ' ') xss:$(wc -l < gf/xss.txt|tr -d ' ') ssrf:$(wc -l < gf/ssrf.txt|tr -d ' ') lfi:$(wc -l < gf/lfi.txt|tr -d ' ') redirect:$(wc -l < gf/redirect.txt|tr -d ' ')"
}
run_stage "Stage 4: gf pattern triage" stage_gf

# ==============================================================================
# STAGE 5 — Param mining (paramspider + arjun)
# ==============================================================================
stage_paramspider() {
  if [[ "${SKIP_PARAMSPIDER}" == "1" ]]; then
    warn "Param mining skipped via flag."
    return 0
  fi
  if [[ "${HAS_TOOL[paramspider]:-0}" != "1" ]] && [[ "${HAS_TOOL[arjun]:-0}" != "1" ]]; then
    warn "Neither paramspider nor arjun installed; skipping."
    return 0
  fi

  if [[ "${HAS_TOOL[paramspider]:-0}" == "1" ]]; then
    step "Run paramspider on apex domain"
    pushd "${TARGET_ROOT}/params" >/dev/null || return 0
    "${TIMEOUT_BIN}" 300 paramspider -d "${DOMAIN}" 2>/dev/null || warn "paramspider failed/timed out."
    popd >/dev/null || true
    # paramspider drops to ./results/<domain>.txt
    if [[ -f "${TARGET_ROOT}/params/results/${DOMAIN}.txt" ]]; then
      mv "${TARGET_ROOT}/params/results/${DOMAIN}.txt" "${TARGET_ROOT}/params/paramspider-raw.txt"
      rmdir "${TARGET_ROOT}/params/results" 2>/dev/null || true
    fi
    if [[ -s params/paramspider-raw.txt ]]; then
      # Extract unique parameter names → wordlist for arjun
      awk -F'?' 'NF>1 {print $2}' params/paramspider-raw.txt \
        | tr '&' '\n' \
        | awk -F'=' 'NF>0 && $1 != "" {print $1}' \
        | sort -u > params/wordlist.txt
      info "paramspider URLs: $(wc -l < params/paramspider-raw.txt | tr -d ' ')"
      info "param wordlist:   $(wc -l < params/wordlist.txt       | tr -d ' ')"
    else
      : > params/wordlist.txt
    fi
  fi

  if [[ "${HAS_TOOL[arjun]:-0}" == "1" ]] && [[ -s alive/live-subs-200-301-302-403.txt ]]; then
    step "Run arjun on alive hosts"
    local arjun_wordlist=""
    [[ -s params/wordlist.txt ]] && arjun_wordlist="-w ${TARGET_ROOT}/params/wordlist.txt"
    "${TIMEOUT_BIN}" 600 arjun \
      -i "${TARGET_ROOT}/alive/live-subs-200-301-302-403.txt" \
      ${arjun_wordlist} \
      -t 10 -d 1 --rate-limit 50 --stable \
      -oT "${TARGET_ROOT}/params/arjun-found.txt" \
      -oJ "${TARGET_ROOT}/params/arjun-found.json" \
      2>/dev/null || warn "arjun failed/timed out."
    [[ -f params/arjun-found.txt ]] && info "arjun discoveries: $(wc -l < params/arjun-found.txt | tr -d ' ')"
  fi
  ping_notify "🔍 Param mining done"
}
run_stage "Stage 5: Param mining (paramspider + arjun)" stage_paramspider

# ==============================================================================
# STAGE 6 — JS URL filtering + download
# ==============================================================================
stage_js_filter() {
  step "Filter JavaScript URLs for hunting focus"
  local JS_ALL=js/js-urls.txt
  local JS_IMP=js/js-urls-important.txt

  if [[ ! -s "${JS_ALL}" ]]; then
    : > "${JS_IMP}"
    return 0
  fi

  if [[ "${JS_DOWNLOAD_MODE}" == "all" ]]; then
    cp "${JS_ALL}" "${JS_IMP}"
  else
    awk -F/ '
      BEGIN { IGNORECASE=1 }
      {
        url=$0; host=$3; path=""
        for (i=4; i<=NF; i++) { if (i>4) path=path"/"; path=path $i }
        sub(/\?.*$/, "", path); path_l=tolower(path)
        n=split(path_l, parts, "/"); file=parts[n]

        if (file ~ /^[a-z]{2}(-[a-z0-9]{2,8})?\.js$/) next
        if (file ~ /^(gtm|gtag|analytics|clarity|hotjar|fbevents|recaptcha|captcha|ga|gtag\.js)\.js$/) next
        if (file ~ /jquery.*\.min\.js$/) next
        if (file ~ /bootstrap.*\.min\.js$/) next

        important=0
        if (file ~ /^(main|runtime|polyfills|app|bundle|vendor|webpack|common)([-._].*)?\.js$/) important=1
        if (file ~ /^([0-9]{1,4}|chunk)([-._].*)?\.js$/) important=1
        if (path_l ~ /(api|auth|login|register|signup|account|user|profile|applicant|appointment|resched|booking|payment|invoice|passport|visa|document|upload|photo|admin|token|session|oauth|sso|otp|verify|graphql|socket|websocket)/) important=1

        if (important) print url
      }
    ' "${JS_ALL}" | sort -u > "${JS_IMP}.raw"

    if [[ "${MAX_JS_PER_HOST}" -gt 0 ]]; then
      awk -F/ -v max="${MAX_JS_PER_HOST}" '{host=$3; if (++c[host] <= max) print $0}' \
        "${JS_IMP}.raw" > "${JS_IMP}"
    else
      cp "${JS_IMP}.raw" "${JS_IMP}"
    fi
    rm -f "${JS_IMP}.raw"

    if [[ ! -s "${JS_IMP}" ]]; then
      warn "Important filter empty — falling back to all JS URLs."
      cp "${JS_ALL}" "${JS_IMP}"
    fi
  fi

  info "JS URLs total:    $(wc -l < "${JS_ALL}" | tr -d ' ')"
  info "JS URLs selected: $(wc -l < "${JS_IMP}" | tr -d ' ')"
}
run_stage "Stage 6a: JS URL filter" stage_js_filter

stage_js_download() {
  if [[ "${SKIP_JS_DOWNLOAD}" == "1" ]]; then
    warn "JS download skipped via flag."
    return 0
  fi

  local JS_IMP=js/js-urls-important.txt
  [[ ! -s "${JS_IMP}" ]] && { warn "No JS URLs to download."; return 0; }

  step "Probe JS hosts to skip dead targets"
  awk -F/ 'NF>3 {print $3}' "${JS_IMP}" | sort -u > js/js-hosts.txt
  : > js/js-responsive-hosts.txt
  while IFS= read -r host; do
    [[ -z "${host}" ]] && continue
    if "${TIMEOUT_BIN}" 10 curl -kIsS --connect-timeout 4 --max-time 8 \
         "https://${host}/" >/dev/null 2>&1 \
       || "${TIMEOUT_BIN}" 10 curl -kIsS --connect-timeout 4 --max-time 8 \
         "http://${host}/" >/dev/null 2>&1; then
      echo "${host}" >> js/js-responsive-hosts.txt
    else
      info "Skipping unreachable JS host: ${host}"
    fi
  done < js/js-hosts.txt

  if [[ -s js/js-responsive-hosts.txt ]]; then
    awk -F/ 'NR==FNR {ok[$1]=1; next} ok[$3] {print $0}' \
      js/js-responsive-hosts.txt "${JS_IMP}" \
      | sort -u > js/js-urls-download.txt
  else
    : > js/js-urls-download.txt
  fi

  info "JS URLs queued for download: $(wc -l < js/js-urls-download.txt | tr -d ' ')"
  if [[ ! -s js/js-urls-download.txt ]]; then return 0; fi

  step "Download JavaScript files (parallel)"
  # Parallel wget via xargs (4 concurrent — gentle on targets)
  xargs -n1 -P4 -I{} bash -c '
    "$0" 40 wget "$1" -P "$2" \
      --content-disposition --trust-server-names \
      --tries=1 --dns-timeout=5 --connect-timeout=5 \
      --read-timeout=15 --timeout=20 --retry-connrefused \
      --no-verbose -e background=off >/dev/null 2>&1
  ' "${TIMEOUT_BIN}" {} "${TARGET_ROOT}/js/Output" < js/js-urls-download.txt || true

  local n; n=$(find js/Output -type f -name '*.js' 2>/dev/null | wc -l | tr -d ' ')
  info "JS files downloaded: ${n}"
  ping_notify "📥 JS download done — ${n} files"
}
run_stage "Stage 6b: JS download" stage_js_download

# ==============================================================================
# STAGE 7 — Secret scanning (trufflehog + gitleaks)
# ==============================================================================
stage_secrets() {
  if [[ "${SKIP_SECRETS}" == "1" ]]; then
    warn "Secret scanning skipped via flag."
    return 0
  fi
  local js_dir="${TARGET_ROOT}/js/Output"
  if [[ ! -d "${js_dir}" ]] || [[ -z "$(ls -A "${js_dir}" 2>/dev/null)" ]]; then
    warn "No downloaded JS files to scan."
    return 0
  fi

  # Build exclusion regex file for trufflehog
  cat > secrets/exclude.txt <<'EOF'
\.min\.js$
\.map$
node_modules/
jquery.*\.js$
bootstrap.*\.js$
react.*\.production\.min\.js$
EOF

  if [[ "${HAS_TOOL[trufflehog]:-0}" == "1" ]]; then
    step "Run trufflehog on JS folder"
    trufflehog filesystem "${js_dir}" \
      --json \
      --results=verified,unknown \
      --no-update \
      --concurrency 8 \
      --force-skip-binaries \
      --force-skip-archives \
      --exclude-paths "${TARGET_ROOT}/secrets/exclude.txt" \
      > secrets/trufflehog.jsonl 2>/dev/null || warn "trufflehog had errors."
    local n; n=$(wc -l < secrets/trufflehog.jsonl | tr -d ' ')
    info "trufflehog findings: ${n}"
    if [[ ${n} -gt 0 ]]; then
      ping_notify "🔥 trufflehog: ${n} potential secrets in JS"
    fi
  fi

  if [[ "${HAS_TOOL[gitleaks]:-0}" == "1" ]]; then
    step "Run gitleaks on JS folder"
    gitleaks dir "${js_dir}" \
      --no-banner \
      --report-format json \
      --report-path "${TARGET_ROOT}/secrets/gitleaks.json" \
      --exit-code 0 \
      --max-target-megabytes 50 \
      2>/dev/null || warn "gitleaks had errors."
    if [[ -f secrets/gitleaks.json ]]; then
      local n; n=$(jq 'length' secrets/gitleaks.json 2>/dev/null || echo 0)
      info "gitleaks findings: ${n}"
      [[ ${n} -gt 0 ]] && ping_notify "🔥 gitleaks: ${n} potential secrets in JS"
    fi
  fi
}
run_stage "Stage 7: Secret scanning" stage_secrets

# ==============================================================================
# STAGE 8 — Content discovery with ffuf
# ==============================================================================
stage_ffuf() {
  if [[ "${SKIP_FFUF}" == "1" ]]; then
    warn "ffuf skipped via flag."
    return 0
  fi
  if [[ "${HAS_TOOL[ffuf]:-0}" != "1" ]]; then
    warn "ffuf not installed."
    return 0
  fi
  if [[ ! -s alive/live-subs-200-301-302-403.txt ]]; then
    warn "No alive hosts for ffuf."
    return 0
  fi

  step "Run ffuf on top-${MAX_FFUF_HOSTS} alive hosts"
  local count=0
  while IFS= read -r url; do
    [[ -z "${url}" ]] && continue
    [[ ${count} -ge ${MAX_FFUF_HOSTS} ]] && break
    count=$(( count + 1 ))

    local safe_name; safe_name="$(echo "${url}" | sed -E 's|https?://||; s|[/:?]|_|g')"
    local out_json="ffuf/${safe_name}.json"

    info "ffuf [${count}/${MAX_FFUF_HOSTS}]: ${url}"
    "${TIMEOUT_BIN}" 600 ffuf \
      -u "${url%/}/FUZZ" \
      -w "${FFUF_WORDLIST}" \
      -mc all -fc 400,401,403,404,500,502 -ac \
      -recursion -recursion-depth 2 \
      -t 40 -rate 100 \
      -timeout 10 -maxtime-job 600 \
      -H 'User-Agent: Mozilla/5.0 (Macintosh; Apple Silicon) MFrecon/2.0' \
      -of json -o "${out_json}" -or \
      -s 2>/dev/null || warn "ffuf job failed for ${url}"
  done < alive/live-subs-200-301-302-403.txt

  ping_notify "📂 ffuf done — ${count} hosts scanned"
}
run_stage "Stage 8: ffuf content discovery" stage_ffuf

# ==============================================================================
# STAGE 9 — dalfox XSS scan
# ==============================================================================
stage_dalfox() {
  if [[ "${SKIP_DALFOX}" == "1" ]]; then
    warn "dalfox skipped via flag."
    return 0
  fi
  if [[ "${HAS_TOOL[dalfox]:-0}" != "1" ]]; then
    warn "dalfox not installed."
    return 0
  fi
  if [[ ! -s gf/xss.txt ]]; then
    warn "gf/xss.txt empty; skipping dalfox."
    return 0
  fi

  step "Run dalfox on gf/xss.txt"
  local extra=()
  [[ -n "${XSS_CALLBACK}" ]] && extra+=( -b "${XSS_CALLBACK}" )

  "${TIMEOUT_BIN}" 1800 dalfox file gf/xss.txt \
    "${extra[@]}" \
    --skip-bav \
    --waf-evasion \
    -w 50 --delay 100 \
    --silence --no-spinner \
    --format json \
    -o dalfox/dalfox-results.json \
    2>/dev/null || warn "dalfox finished with errors/timeout."

  if [[ -f dalfox/dalfox-results.json ]]; then
    local n; n=$(jq 'length' dalfox/dalfox-results.json 2>/dev/null || echo 0)
    info "dalfox findings: ${n}"
    [[ ${n} -gt 0 ]] && ping_notify "💥 dalfox: ${n} XSS candidates"
  fi
}
run_stage "Stage 9: dalfox XSS" stage_dalfox

# ==============================================================================
# STAGE 10 — Nuclei standard scan (alive hosts)
# ==============================================================================
stage_nuclei_standard() {
  if [[ "${SKIP_NUCLEI}" == "1" ]]; then
    warn "Nuclei skipped via flag."
    return 0
  fi
  if [[ "${HAS_TOOL[nuclei]:-0}" != "1" ]]; then
    warn "nuclei not installed."
    return 0
  fi
  if [[ ! -s alive/live-subs.urls ]]; then
    warn "No alive hosts for nuclei."
    return 0
  fi

  step "Update nuclei templates"
  nuclei -ut -duc -silent 2>/dev/null || warn "Template update failed (continuing)."

  step "Run nuclei standard scan"
  nuclei \
    -l alive/live-subs.urls \
    -as \
    -severity critical,high,medium,low \
    -tags cve,oast,exposure,misconfig,takeover,default-login,exposed-panels,tech \
    -etags dos,intrusive,fuzz \
    -duc \
    -rl "${NUCLEI_RL}" -bs 25 -c 25 -ss host-spray \
    -timeout 10 -retries 1 -mhe 30 \
    -H 'User-Agent: Mozilla/5.0 (Macintosh; Apple Silicon) MFrecon/2.0' \
    -stats -si 30 \
    -o nuclei_results/standard.txt \
    -je nuclei_results/standard.jsonl \
    -sresp -srd nuclei_results/responses \
    2>nuclei_results/standard.err || warn "nuclei standard scan exited non-zero."

  local n; n=$(wc -l < nuclei_results/standard.txt 2>/dev/null | tr -d ' ' || echo 0)
  info "nuclei standard findings: ${n}"

  # Notify on criticals immediately
  if [[ -f nuclei_results/standard.jsonl ]]; then
    local crits; crits=$(jq -rc 'select(.info.severity=="critical") | "🚨 CRITICAL: \(.info.name) — \(.matched-at)"' \
                          nuclei_results/standard.jsonl 2>/dev/null | head -20)
    if [[ -n "${crits}" ]]; then
      while IFS= read -r line; do
        [[ -n "${line}" ]] && ping_notify "${line}"
      done <<< "${crits}"
    fi
  fi
  ping_notify "🛡 Nuclei standard done — ${n} findings"
}
run_stage "Stage 10: Nuclei standard scan" stage_nuclei_standard

# ==============================================================================
# STAGE 11 — Nuclei DAST scan (params.txt)
# ==============================================================================
stage_nuclei_dast() {
  if [[ "${SKIP_NUCLEI}" == "1" ]] || [[ "${SKIP_DAST}" == "1" ]]; then
    warn "Nuclei DAST skipped via flag."
    return 0
  fi
  if [[ "${HAS_TOOL[nuclei]:-0}" != "1" ]]; then
    warn "nuclei not installed."
    return 0
  fi

  # Build a clean params-only target file (URLs that have ?key=value)
  if command -v qsreplace >/dev/null 2>&1; then
    grep -E '\?[a-zA-Z_][^=]*=' urls/all-urls.txt 2>/dev/null \
      | qsreplace -a | sort -u > urls/params.txt
  else
    grep -E '\?[a-zA-Z_][^=]*=' urls/all-urls.txt 2>/dev/null \
      | sort -u > urls/params.txt
  fi

  # Also fold in arjun discoveries
  if [[ -s params/arjun-found.txt ]]; then
    cat params/arjun-found.txt | sort -u >> urls/params.txt
    sort -u urls/params.txt -o urls/params.txt
  fi

  if [[ ! -s urls/params.txt ]]; then
    warn "No parameterized URLs for DAST."
    return 0
  fi

  info "DAST input: $(wc -l < urls/params.txt | tr -d ' ') URLs"

  step "Run nuclei DAST scan"
  nuclei \
    -l urls/params.txt \
    -dast \
    -fa "${NUCLEI_FA}" \
    -severity critical,high,medium \
    -tags sqli,xss,ssrf,rce,lfi,redirect,ssti,crlf \
    -duc \
    -rl "${NUCLEI_DAST_RL}" -bs 25 -c 25 \
    -timeout 15 -retries 1 \
    -H 'User-Agent: Mozilla/5.0 (Macintosh; Apple Silicon) MFrecon/2.0' \
    -dfp \
    -stats -si 30 \
    -o nuclei_results/dast.txt \
    -je nuclei_results/dast.jsonl \
    -dtr nuclei_results/dast-report.txt \
    2>nuclei_results/dast.err || warn "nuclei DAST scan exited non-zero."

  local n; n=$(wc -l < nuclei_results/dast.txt 2>/dev/null | tr -d ' ' || echo 0)
  info "nuclei DAST findings: ${n}"

  # Notify on highs/criticals
  if [[ -f nuclei_results/dast.jsonl ]]; then
    local hits; hits=$(jq -rc 'select(.info.severity=="critical" or .info.severity=="high") | "🚨 \(.info.severity|ascii_upcase): \(.info.name) — \(.matched-at)"' \
                       nuclei_results/dast.jsonl 2>/dev/null | head -20)
    if [[ -n "${hits}" ]]; then
      while IFS= read -r line; do
        [[ -n "${line}" ]] && ping_notify "${line}"
      done <<< "${hits}"
    fi
  fi
  ping_notify "💉 Nuclei DAST done — ${n} findings"
}
run_stage "Stage 11: Nuclei DAST scan" stage_nuclei_dast

# ==============================================================================
# STAGE 12 — AI handoff guide
# ==============================================================================
stage_ai_handoff() {
  step "Write AI handoff guide"
  cat > NEXT_STEPS_AI.md <<EOF
# AI Handoff — ${DOMAIN}

Run date: $(date)
Output root: ${TARGET_ROOT}

---

## Prompt 1 — JS triage
Analyze \`js/Output\` (downloaded JavaScript files) from the production app.

Phase 1:
1. Build an inventory of all JS files.
2. Identify likely app code vs vendor/framework/minified library code.
3. Extract and deduplicate:
   - API endpoints
   - GraphQL endpoints, queries, and mutations
   - WebSocket endpoints
   - Internal URLs, hostnames, IPs, S3/bucket references
   - Tokens, keys, secrets, credentials, suspicious constants
4. Identify files containing security-relevant logic: auth, role checks, admin features, payment, booking, applicant/profile handling, upload/document/photo/facial verification flows.
5. Flag files with comments, debug code, feature flags, or disabled security checks.

Phase 2:
For the most interesting files explain:
- why the file matters
- what sensitive functionality it contains
- what endpoints and parameters appear important
- whether access control appears client-side only
- whether IDs like userId, applicantId, appointmentId, slotId, paymentId, profileId are present
- whether there are hidden or undocumented routes not obvious from the UI

Output to \`js/Output/\`:
1. inventory.md
2. interesting-files.txt
3. endpoints.txt
4. graphql.txt
5. websocket.txt
6. internal-assets.txt
7. secrets-findings.md
8. suspicious-client-side-controls.md
9. final-summary.md

## Prompt 2 — Burp manual testing shortlist
Using the previous analysis, create a manual testing shortlist for Burp.
For each high-value endpoint or JS-discovered function, provide:
- endpoint/path
- likely method
- key parameters/IDs
- why it is suspicious
- specific manual tests for IDOR, auth bypass, workflow bypass, reschedule tampering, photo tampering, payment tampering, hidden admin access

Output: \`${TARGET_ROOT}/burp-to/burp_manual_testing_shortlist.csv\`

## Prompt 3 — Burp request templates
From \`burp-to/burp_manual_testing_shortlist.csv\`, generate ready-to-paste Burp Repeater requests for the highest-value hosts.

Start with these hosts first (highest value):
$(head -n 10 alive/live-subs-200-301-302-403.txt 2>/dev/null | sed 's/^/- /')

Output to: \`${TARGET_ROOT}/burp-to/\`

---

## Findings snapshot
- Subdomains: $(wc -l < subs/all-subs.txt 2>/dev/null | tr -d ' ')
- Live hosts: $(wc -l < alive/live-subs-200-301-302-403.txt 2>/dev/null | tr -d ' ')
- URLs: $(wc -l < urls/all-urls.txt 2>/dev/null | tr -d ' ')
- Parameterized URLs: $(wc -l < urls/params.txt 2>/dev/null | tr -d ' ')
- gf/sqli: $(wc -l < gf/sqli.txt 2>/dev/null | tr -d ' ')
- gf/xss: $(wc -l < gf/xss.txt 2>/dev/null | tr -d ' ')
- gf/ssrf: $(wc -l < gf/ssrf.txt 2>/dev/null | tr -d ' ')
- gf/lfi: $(wc -l < gf/lfi.txt 2>/dev/null | tr -d ' ')
- gf/redirect: $(wc -l < gf/redirect.txt 2>/dev/null | tr -d ' ')
- nuclei standard: $(wc -l < nuclei_results/standard.txt 2>/dev/null | tr -d ' ')
- nuclei DAST: $(wc -l < nuclei_results/dast.txt 2>/dev/null | tr -d ' ')
- dalfox: $(jq 'length' dalfox/dalfox-results.json 2>/dev/null || echo 0)
- trufflehog secrets: $(wc -l < secrets/trufflehog.jsonl 2>/dev/null | tr -d ' ')
- gitleaks secrets: $(jq 'length' secrets/gitleaks.json 2>/dev/null || echo 0)
EOF
  info "Wrote ${TARGET_ROOT}/NEXT_STEPS_AI.md"
}
run_stage "Stage 12: AI handoff guide" stage_ai_handoff

# ==============================================================================
# DONE
# ==============================================================================
TOTAL_DUR=$(awk -F, 'NR>1 {s+=$4} END {print s}' "${TIMING_FILE}" 2>/dev/null || echo "?")
SUMMARY="✅ MFrecon completed for ${DOMAIN} in ${TOTAL_DUR}s
Subs: $(wc -l < subs/all-subs.txt 2>/dev/null | tr -d ' ') | Live: $(wc -l < alive/live-subs-200-301-302-403.txt 2>/dev/null | tr -d ' ') | URLs: $(wc -l < urls/all-urls.txt 2>/dev/null | tr -d ' ') | Params: $(wc -l < urls/params.txt 2>/dev/null | tr -d ' ')
Nuclei std: $(wc -l < nuclei_results/standard.txt 2>/dev/null | tr -d ' ') | DAST: $(wc -l < nuclei_results/dast.txt 2>/dev/null | tr -d ' ') | dalfox: $(jq 'length' dalfox/dalfox-results.json 2>/dev/null || echo 0)
Output: ${TARGET_ROOT}"

step "Summary"
printf "%s\n" "${SUMMARY}"
ping_notify "${SUMMARY}"

exit 0
