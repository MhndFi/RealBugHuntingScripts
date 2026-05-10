# MFrecon

12-stage bug bounty recon + active scanning pipeline for a single root domain.
Built and tuned for **macOS Apple Silicon**.

---

## Who this is for

Practitioner-level bug bounty hunters working public/private programs on HackerOne,
Bugcrowd, etc. The script assumes you already know what CSRF, IDOR, SSRF, SSTI,
DAST, and a WAF are — there are no 101 explanations or hand-holding.

You bring scope and judgment; MFrecon brings a clean corpus + first-pass active scan
to drive your manual testing in Burp.

---

## Install (one-time)

```zsh
git clone https://github.com/MhndFi/RealBugHuntingScripts.git
cd RealBugHuntingScripts/recon
chmod +x setup-toolchain.sh MFrecon.sh
./setup-toolchain.sh
```

Installs Homebrew, GNU userland, Go, Python, the ProjectDiscovery suite (subfinder,
httpx, katana, nuclei, notify), tomnomnom tools (gf, qsreplace, assetfinder,
waybackurls), gau, amass, ffuf, dalfox, trufflehog, gitleaks, paramspider, arjun,
SecLists, gf-patterns, and nuclei templates.

Open a new terminal afterwards (or `source ~/.zshrc`).

---

## Run

```zsh
./MFrecon.sh example.com
```

Output lands in `~/targets/example.com/`.

Common flags:

| Flag | What it does |
|---|---|
| `-o ~/recon/acme` | custom output dir |
| `--skip-nuclei` | skip both nuclei passes |
| `--skip-dast` | skip nuclei DAST only (keep standard) |
| `--skip-ffuf` | skip content fuzzing (use on programs that disallow brute force) |
| `--skip-dalfox` | skip XSS scanning |
| `--skip-secrets` | skip trufflehog + gitleaks |
| `--skip-notify` | disable Discord/Slack/Telegram pings |
| `--xss-callback https://yourcb.xss.ht` | dalfox blind XSS callback |
| `--max-ffuf-hosts 10` | cap ffuf to top-N alive hosts (default 20) |
| `--nuclei-fa low` | nuclei DAST aggression: low/medium/high |

Full flag list: `./MFrecon.sh --help`.

---

## Pipeline

| # | Stage | Tools |
|---|---|---|
| 1 | Subdomain enum | subfinder, assetfinder, amass, crt.sh, wayback CDX |
| 2 | Live host probe | httpx |
| 3 | URL collection | wayback, gau, katana |
| 4 | Pattern triage | gf (sqli, xss, ssrf, lfi, redirect, rce, ssti, idor) |
| 5 | Param mining | paramspider, arjun |
| 6 | JS filter + download | wget |
| 7 | Secret scanning | trufflehog, gitleaks |
| 8 | Content fuzzing | ffuf (raft-medium-directories) |
| 9 | XSS scanning | dalfox |
| 10 | Nuclei standard | CVEs, exposures, misconfigs, takeovers |
| 11 | Nuclei DAST | sqli/xss/ssrf/lfi/redirect/ssti/rce on params |
| 12 | AI handoff guide | `NEXT_STEPS_AI.md` for downstream LLM-assisted JS triage |

Stages are sequential — each depends on prior outputs.

---

## Output layout

```
~/targets/<domain>/
├── subs/        all-subs.txt
├── alive/       live-subs-*.txt
├── urls/        all-urls.txt, params.txt, interesting.txt, api.txt
├── js/          js-urls-important.txt, Output/*.js
├── gf/          {sqli,xss,ssrf,lfi,redirect,rce,ssti,idor}.txt
├── params/      paramspider-raw.txt, wordlist.txt, arjun-found.txt
├── ffuf/        <host>.json
├── dalfox/      dalfox-results.json
├── secrets/     trufflehog.jsonl, gitleaks.json
├── nuclei_results/  standard.{txt,jsonl}, dast.{txt,jsonl}, responses/
├── burp-to/     manual-testing CSVs/templates (you populate)
├── logs/        run-<ts>.log, stage-timing.csv
└── NEXT_STEPS_AI.md
```

---

## Notify (optional)

Long runs (30 min – 2 h) ping every milestone + criticals to your phone via
ProjectDiscovery's `notify`. Edit `~/.config/notify/provider-config.yaml` and
plug in a Discord webhook, Slack webhook, or Telegram bot token + chat ID.

Test:
```zsh
echo "test" | notify -id default
```

Skip per-run with `--skip-notify`, or leave the config untouched — the script
swallows notify errors and keeps running.

---

## Notes

- `set -uo pipefail` only — **not** `-e`. Bug bounty tools fail constantly
  (timeouts, no findings, WAFs); each stage handles its own errors.
- Auto-`exec`s under bash 5 if launched under macOS bash 3.2.
- `gtimeout` (coreutils) used on macOS, `timeout` on Linux — auto-detected.
- Designed for a single root domain per run. For multi-root targets, run once
  per root.
