#!/usr/bin/env bash
# ==============================================================================
# setup-toolchain.sh — one-time installer for MFrecon.sh on macOS Apple Silicon
# ==============================================================================
# Installs everything MFrecon.sh needs:
#   - Homebrew (if missing)
#   - GNU userland (coreutils, gnu-sed, grep, findutils, gawk)
#   - bash 5, go, python@3.12, jq, pipx, curl, wget, git
#   - Active scanning tools: nuclei, ffuf, dalfox, trufflehog, gitleaks
#   - ProjectDiscovery suite: subfinder, httpx, katana, notify, qsreplace
#   - Recon: assetfinder, waybackurls, gau, amass
#   - Param mining: arjun (pipx), paramspider (pipx from source)
#   - Pattern triage: gf + tomnomnom/Gf-Patterns + 1ndianl33t/Gf-Patterns
#   - Wordlists: SecLists
#   - Templates: nuclei -ut
#   - Notify config skeleton
# ==============================================================================

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer is for macOS only." >&2
  exit 1
fi

ARCH="$(uname -m)"
echo "[i] Detected macOS / ${ARCH}"

# ------------------------------------------------------------------------------
# 1. Homebrew
# ------------------------------------------------------------------------------
if ! command -v brew >/dev/null 2>&1; then
  echo "[*] Installing Homebrew..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

if [[ "${ARCH}" == "arm64" ]]; then
  eval "$(/opt/homebrew/bin/brew shellenv)"
else
  eval "$(/usr/local/bin/brew shellenv)"
fi

# ------------------------------------------------------------------------------
# 2. Core packages + GNU userland
# ------------------------------------------------------------------------------
echo "[*] Installing core packages..."
brew install \
  bash go python@3.12 git jq curl wget pipx \
  coreutils gnu-sed grep findutils gawk gnu-tar \
  ffuf dalfox trufflehog gitleaks

pipx ensurepath

# Ensure pipx user bin is on PATH for THIS shell so verification at the end works.
export PATH="${HOME}/.local/bin:${PATH}"

# ------------------------------------------------------------------------------
# 3. Go-based tools (ProjectDiscovery + tomnomnom + lc)
# ------------------------------------------------------------------------------
export GOPATH="${HOME}/go"
export PATH="${GOPATH}/bin:$(brew --prefix)/bin:${PATH}"

echo "[*] Installing Go tools..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/tomnomnom/qsreplace@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/owasp-amass/amass/v4/...@master

# ------------------------------------------------------------------------------
# 4. Python tools via pipx
# ------------------------------------------------------------------------------
echo "[*] Installing Python tools..."
pipx install arjun || pipx upgrade arjun || true

if [[ ! -d /tmp/paramspider ]]; then
  git clone --depth 1 https://github.com/devanshbatham/ParamSpider /tmp/paramspider
fi
pipx install /tmp/paramspider --force || true

pipx install uro || pipx upgrade uro || true

# ------------------------------------------------------------------------------
# 5. gf patterns
# ------------------------------------------------------------------------------
echo "[*] Installing gf patterns..."
mkdir -p "${HOME}/.gf"

if [[ ! -d /tmp/gf-src ]]; then
  git clone --depth 1 https://github.com/tomnomnom/gf /tmp/gf-src
fi
cp -rn /tmp/gf-src/examples/* "${HOME}/.gf/" 2>/dev/null || true

if [[ ! -d /tmp/gf-pat ]]; then
  git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-pat
fi
cp -n /tmp/gf-pat/*.json "${HOME}/.gf/" 2>/dev/null || true

# ------------------------------------------------------------------------------
# 6. SecLists
# ------------------------------------------------------------------------------
SECLISTS_DIR="$(brew --prefix)/share/seclists"
if [[ ! -d "${SECLISTS_DIR}" ]]; then
  echo "[*] Cloning SecLists into ${SECLISTS_DIR}..."
  git clone --depth 1 https://github.com/danielmiessler/SecLists "${SECLISTS_DIR}"
else
  echo "[i] SecLists already present at ${SECLISTS_DIR}"
fi

# ------------------------------------------------------------------------------
# 7. Nuclei templates
# ------------------------------------------------------------------------------
echo "[*] Updating nuclei templates..."
# NOTE: do NOT pass -silent — it suppresses the first-time install on some nuclei builds
# and you end up with no templates dir at all. Verbose is fine; we want to see the result.
nuclei -ut -duc || echo "[!] nuclei template update failed (run manually later)."

# ------------------------------------------------------------------------------
# 8. Notify config skeleton
# ------------------------------------------------------------------------------
mkdir -p "${HOME}/.config/notify"
NOTIFY_CFG="${HOME}/.config/notify/provider-config.yaml"
if [[ ! -f "${NOTIFY_CFG}" ]]; then
  cat > "${NOTIFY_CFG}" <<'EOF'
# Replace REPLACE_ME values with your real webhook URLs.
# Get a Discord webhook: Server Settings → Integrations → Webhooks → New Webhook
# Get a Slack webhook:   https://api.slack.com/apps → Incoming Webhooks
discord:
  - id: "default"
    discord_channel: "recon"
    discord_username: "MFrecon"
    discord_format: "{{data}}"
    discord_webhook_url: "REPLACE_ME"

# slack:
#   - id: "slack-default"
#     slack_channel: "#recon"
#     slack_username: "MFrecon"
#     slack_format: "{{data}}"
#     slack_webhook_url: "REPLACE_ME"
EOF
  echo "[i] Created ${NOTIFY_CFG} — edit it with your webhook URL."
fi

# ------------------------------------------------------------------------------
# 9. zshrc additions (idempotent)
# ------------------------------------------------------------------------------
ZSHRC="${HOME}/.zshrc"
if ! grep -q 'GNU userland for MFrecon' "${ZSHRC}" 2>/dev/null; then
  cat >> "${ZSHRC}" <<'EOF'

# === GNU userland for MFrecon (macOS portability) ===
if [[ "$(uname -m)" == "arm64" ]]; then
  eval "$(/opt/homebrew/bin/brew shellenv)"
else
  eval "$(/usr/local/bin/brew shellenv)"
fi
export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:$HOME/.local/bin:$(brew --prefix)/bin:$PATH"
for pkg in coreutils gnu-sed grep findutils gawk; do
  GNUBIN="$(brew --prefix "$pkg" 2>/dev/null)/libexec/gnubin"
  [[ -d "$GNUBIN" ]] && PATH="$GNUBIN:$PATH"
done
export PATH
ulimit -n 12288 2>/dev/null
# === end MFrecon block ===
EOF
  echo "[i] Added shell init block to ${ZSHRC}"
fi

# ------------------------------------------------------------------------------
# 10. Verification
# ------------------------------------------------------------------------------
echo
echo "[*] Verifying installations..."
fail=0
for tool in subfinder assetfinder amass httpx katana gau \
            nuclei ffuf dalfox trufflehog gitleaks \
            gf qsreplace notify arjun paramspider \
            jq curl wget go python3.12 pipx \
            gtimeout gsed ggrep gawk; do
  if command -v "${tool}" >/dev/null 2>&1; then
    printf "  ✅ %s\n" "${tool}"
  else
    printf "  ❌ %s (missing)\n" "${tool}"
    fail=$(( fail + 1 ))
  fi
done

echo
if [[ ${fail} -eq 0 ]]; then
  echo "✅ Toolchain installed successfully."
else
  echo "⚠ ${fail} tool(s) missing — re-run setup or install manually."
fi

cat <<EOF

Next steps:
  1. Open a NEW terminal (or run:  source ~/.zshrc)
  2. Edit ${NOTIFY_CFG} and replace REPLACE_ME with your Discord webhook URL
  3. Test notify:  echo "test from \$(hostname)" | notify -id default
  4. Run recon:    ./MFrecon.sh example.com
EOF
