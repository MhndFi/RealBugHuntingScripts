#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

APP_NAME = "MFRecon"
APP_VERSION = "1.0.0"
USER_AGENT = f"{APP_NAME}/{APP_VERSION}"
SSL_CONTEXT = ssl.create_default_context()
STOP_EVENT = threading.Event()

INTERESTING_URL_RE = re.compile(
    r"login|register|signup|account|user|profile|applicant|appointment|reschedule|payment|pay|invoice|"
    r"verify|verification|photo|upload|document|passport|visa|api|auth|token",
    re.I,
)
API_URL_RE = re.compile(r"/api/|graphql|swagger|openapi|/v[0-9]+/|\brest\b", re.I)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)

STATIC_EXTENSIONS = {
    ".7z", ".aac", ".avi", ".avif", ".bak", ".bin", ".bmp", ".bz2", ".class", ".css", ".csv",
    ".deb", ".dll", ".dmg", ".doc", ".docx", ".eot", ".epub", ".exe", ".gif", ".gz", ".ico",
    ".img", ".iso", ".jar", ".jpeg", ".jpg", ".map", ".mkv", ".mov", ".mp3", ".mp4", ".mpeg",
    ".mpg", ".msi", ".ogg", ".otf", ".pdf", ".pem", ".png", ".ppt", ".pptx", ".rar", ".rpm",
    ".scss", ".svg", ".tar", ".tgz", ".ttf", ".txt", ".wav", ".webm", ".webp", ".woff", ".woff2",
    ".xls", ".xlsx", ".xml", ".xz", ".yaml", ".yml", ".zip",
}

SENSITIVE_FILE_EXTENSIONS = {
    ".xls", ".xml", ".xlsx", ".json", ".pdf", ".sql", ".doc", ".docx", ".pptx", ".txt", ".git",
    ".zip", ".tar.gz", ".tgz", ".bak", ".7z", ".rar", ".log", ".cache", ".secret", ".db", ".backup",
    ".yml", ".gz", ".config", ".csv", ".yaml", ".md", ".md5", ".exe", ".dll", ".bin", ".ini",
    ".bat", ".sh", ".tar", ".deb", ".rpm", ".iso", ".img", ".env", ".apk", ".msi", ".dmg", ".tmp",
    ".crt", ".pem", ".key", ".pub", ".asc",
}

JS_TRACKER_RE = re.compile(r"^(gtm|gtag|analytics|clarity|hotjar|fbevents|recaptcha|captcha)\.js$", re.I)
JS_LOCALE_RE = re.compile(r"^[a-z]{2}(?:-[a-z0-9]{2,8})?\.js$", re.I)
JS_IMPORTANT_FILE_RE = re.compile(
    r"^(main|runtime|polyfills|app|bundle|vendor|webpack|common)([-._].*)?\.js$|^([0-9]{1,4}|chunk)([-._].*)?\.js$",
    re.I,
)
JS_IMPORTANT_PATH_RE = re.compile(
    r"api|auth|login|register|signup|account|user|profile|applicant|appointment|resched|booking|payment|"
    r"invoice|passport|visa|document|upload|photo|admin|token|session|oauth|sso|otp|verify|graphql|socket|websocket",
    re.I,
)

VT_DOMAIN_RELATIONSHIP_PATHS = ["subdomains", "resolutions"]
LOCAL_ENV_PATHS = (
    Path.cwd() / ".env",
    Path(__file__).resolve().parent.parent / ".env",
)


def parse_env_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def load_local_env(paths: Sequence[Path]) -> None:
    for path in paths:
        try:
            if not path.exists():
                continue
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                entry = line.strip()
                if not entry or entry.startswith("#"):
                    continue
                if entry.startswith("export "):
                    entry = entry[7:].strip()
                if "=" not in entry:
                    continue
                key, value = entry.split("=", 1)
                key = key.strip()
                if not key or key in os.environ:
                    continue
                os.environ[key] = parse_env_value(value)
        except OSError:
            continue


def handle_signal(signum: int, _frame: Any) -> None:
    STOP_EVENT.set()
    print(f"\n[!] Received signal {signum}. Stopping after current step...", file=sys.stderr)


class Colors:
    enabled = sys.stdout.isatty()
    CYAN = "\033[36m" if enabled else ""
    GREEN = "\033[32m" if enabled else ""
    YELLOW = "\033[33m" if enabled else ""
    RED = "\033[31m" if enabled else ""
    BOLD = "\033[1m" if enabled else ""
    RESET = "\033[0m" if enabled else ""


def info(message: str) -> None:
    print(f"{Colors.GREEN}[i]{Colors.RESET} {message}")


def step(message: str) -> None:
    print(f"\n{Colors.BOLD}{Colors.CYAN}==>{Colors.RESET} {message}")


def warn(message: str) -> None:
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {message}", file=sys.stderr)


def error(message: str) -> None:
    print(f"{Colors.RED}[-]{Colors.RESET} {message}", file=sys.stderr)


class JsonLogger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(self, level: str, event: str, **fields: Any) -> None:
        record = {
            "ts": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "level": level,
            "event": event,
            **fields,
        }
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")


class ResumeState:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = {"stages": {}}
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self.data = {"stages": {}}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")

    def is_done(self, stage: str) -> bool:
        return bool(self.data.get("stages", {}).get(stage, {}).get("done"))

    def mark_started(self, stage: str) -> None:
        self.data.setdefault("stages", {}).setdefault(stage, {})
        self.data["stages"][stage].update(
            {"done": False, "started_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"}
        )
        self.save()

    def mark_done(self, stage: str, **extra: Any) -> None:
        self.data.setdefault("stages", {}).setdefault(stage, {})
        self.data["stages"][stage].update(
            {"done": True, "finished_at": dt.datetime.utcnow().isoformat(timespec="seconds") + "Z", **extra}
        )
        self.save()


@dataclass
class ToolInfo:
    name: str
    path: str | None
    optional: bool = False


@dataclass
class RunConfig:
    target: str | None
    targets_file: str | None
    output_dir: str | None
    templates_dir: str | None
    threads: int
    rate_limit: int
    timeout: int
    resume: bool
    skip_dirsearch: bool
    skip_nuclei: bool
    skip_js_download: bool
    js_mode: str
    max_js_per_host: int
    dirsearch_wordlist: str | None
    dirsearch_extensions: str | None
    severity: str
    vt_api_key: str | None
    vt_limit: int
    nuclei_rate_limit: int
    nuclei_bulk_size: int
    nuclei_concurrency: int
    katana_depth: int


@dataclass
class OutputPaths:
    root: Path
    subs: Path
    alive: Path
    urls: Path
    js: Path
    js_output: Path
    js_downloaded: Path
    nuclei: Path
    burp_to: Path
    logs: Path
    vt: Path
    state: Path
    project: Path

    @classmethod
    def create(cls, root: Path) -> "OutputPaths":
        paths = cls(
            root=root,
            subs=root / "subs",
            alive=root / "alive",
            urls=root / "urls",
            js=root / "js",
            js_output=root / "js" / "Output",
            js_downloaded=root / "js" / "downloaded",
            nuclei=root / "nuclei_results",
            burp_to=root / "burp-to",
            logs=root / "logs",
            vt=root / "vt",
            state=root / ".resume.json",
            project=root / "nuclei_results" / "project",
        )
        for path in [
            paths.root,
            paths.subs,
            paths.alive,
            paths.urls,
            paths.js,
            paths.js_output,
            paths.js_downloaded,
            paths.nuclei,
            paths.burp_to,
            paths.logs,
            paths.vt,
            paths.project,
        ]:
            path.mkdir(parents=True, exist_ok=True)
        return paths


def parse_args() -> RunConfig:
    load_local_env(LOCAL_ENV_PATHS)
    parser = argparse.ArgumentParser(
        description="Python rewrite of MFrecon.sh with prompt-style pipeline and your recon add-ons.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="Single target domain or URL")
    parser.add_argument("-l", "--list", dest="targets_file", help="File containing targets (one per line)")
    parser.add_argument("-o", "--output-dir", help="Exact output folder for a single target, or parent folder for --list")
    parser.add_argument("-t", "--templates-dir", help="Nuclei templates directory")
    parser.add_argument("--threads", type=int, default=50, help="General concurrency for supported tools")
    parser.add_argument("--rate-limit", type=int, default=150, help="General rate limit for supported tools")
    parser.add_argument("--timeout", type=int, default=20, help="Base timeout in seconds for network operations")
    parser.add_argument("--resume", action="store_true", help="Resume completed work from the output folder")
    parser.add_argument("--skip-dirsearch", action="store_true", help="Skip dirsearch stage")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip all nuclei stages")
    parser.add_argument("--skip-js-download", action="store_true", help="Do not download JavaScript files")
    parser.add_argument("--js-mode", choices=["important", "all", "off"], default="important", help="JavaScript selection mode")
    parser.add_argument("--max-js-per-host", type=int, default=30, help="Max selected JS files per host in important mode")
    parser.add_argument("--dirsearch-wordlist", help="Custom dirsearch wordlist path")
    parser.add_argument("--dirsearch-extensions", default="php,aspx,jsp,html,js,txt,json,xml", help="Dirsearch extensions list")
    parser.add_argument("--severity", default="medium,high,critical", help="Nuclei severity filter for parameter URL scan")
    parser.add_argument(
        "--vt-api-key",
        default=None,
        help="Optional VirusTotal API key or comma-separated keys; also reads VT_API_KEY/VT_API_KEYS from .env or shell env",
    )
    parser.add_argument("--vt-limit", type=int, default=40, help="Max VirusTotal relationship objects to request per relationship")
    parser.add_argument("--nuclei-rate-limit", type=int, default=75, help="Nuclei requests per second")
    parser.add_argument("--nuclei-bulk-size", type=int, default=25, help="Nuclei bulk size")
    parser.add_argument("--nuclei-concurrency", type=int, default=10, help="Nuclei template concurrency")
    parser.add_argument("--katana-depth", type=int, default=3, help="Katana crawl depth")
    args = parser.parse_args()

    if not args.target and not args.targets_file:
        parser.error("provide a target or use -l/--list")
    if args.target and args.targets_file:
        parser.error("use either a single target or -l/--list, not both")

    return RunConfig(
        target=args.target,
        targets_file=args.targets_file,
        output_dir=args.output_dir,
        templates_dir=args.templates_dir,
        threads=max(1, args.threads),
        rate_limit=max(1, args.rate_limit),
        timeout=max(5, args.timeout),
        resume=args.resume,
        skip_dirsearch=args.skip_dirsearch,
        skip_nuclei=args.skip_nuclei,
        skip_js_download=args.skip_js_download,
        js_mode=args.js_mode,
        max_js_per_host=max(1, args.max_js_per_host),
        dirsearch_wordlist=args.dirsearch_wordlist,
        dirsearch_extensions=args.dirsearch_extensions,
        severity=args.severity,
        vt_api_key=args.vt_api_key or os.environ.get("VT_API_KEY") or os.environ.get("VT_API_KEYS"),
        vt_limit=max(1, args.vt_limit),
        nuclei_rate_limit=max(1, args.nuclei_rate_limit),
        nuclei_bulk_size=max(1, args.nuclei_bulk_size),
        nuclei_concurrency=max(1, args.nuclei_concurrency),
        katana_depth=max(1, args.katana_depth),
    )


def normalize_target(raw: str) -> str | None:
    value = raw.strip()
    if not value or value.startswith("#"):
        return None
    if "://" in value:
        parsed = urlsplit(value)
        host = parsed.netloc or parsed.path
    else:
        host = value.split("/")[0]
    host = host.split("@")[ -1 ]
    host = host.split(":")[0].strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host:
        return None
    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return None
    return host


def load_targets(config: RunConfig) -> list[str]:
    raw_targets: list[str] = []
    if config.target:
        raw_targets.append(config.target)
    if config.targets_file:
        path = Path(config.targets_file).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"targets file not found: {path}")
        raw_targets.extend(path.read_text(encoding="utf-8", errors="ignore").splitlines())

    seen: set[str] = set()
    targets: list[str] = []
    for raw in raw_targets:
        normalized = normalize_target(raw)
        if normalized and normalized not in seen:
            seen.add(normalized)
            targets.append(normalized)
    if not targets:
        raise ValueError("no valid targets found")
    return targets


def resolve_output_root(config: RunConfig, target: str, total_targets: int) -> Path:
    if config.output_dir:
        base = Path(config.output_dir).expanduser().resolve(strict=False)
        if total_targets == 1 and config.target:
            return base
        return base / target
    return (Path.home() / "targets" / target).resolve(strict=False)


def detect_tools(config: RunConfig) -> dict[str, ToolInfo]:
    dirsearch_path = shutil.which("dirsearch") or shutil.which("dirsearch.py")
    tools = {
        "subfinder": ToolInfo("subfinder", shutil.which("subfinder"), optional=False),
        "assetfinder": ToolInfo("assetfinder", shutil.which("assetfinder"), optional=True),
        "amass": ToolInfo("amass", shutil.which("amass"), optional=True),
        "httpx": ToolInfo("httpx", shutil.which("httpx"), optional=False),
        "gau": ToolInfo("gau", shutil.which("gau"), optional=False),
        "katana": ToolInfo("katana", shutil.which("katana"), optional=False),
        "dirsearch": ToolInfo("dirsearch", dirsearch_path, optional=True),
        "nuclei": ToolInfo("nuclei", shutil.which("nuclei"), optional=config.skip_nuclei),
    }
    missing_required = [name for name, tool in tools.items() if not tool.optional and not tool.path]
    if missing_required:
        raise RuntimeError(f"missing required tools: {', '.join(missing_required)}")
    return tools


def read_lines(path: Path) -> Iterator[str]:
    if not path.exists():
        return iter(())
    def _iter() -> Iterator[str]:
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield line
    return _iter()


def write_lines(path: Path, lines: Iterable[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as fh:
        for line in lines:
            if not line:
                continue
            fh.write(line + "\n")
            count += 1
    return count


def dedupe_preserve_order(lines: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for line in lines:
        if not line or line in seen:
            continue
        seen.add(line)
        output.append(line)
    return output


def normalize_hostname(host: str) -> str:
    host = ANSI_RE.sub("", host).strip().lower().rstrip(".")
    if "://" in host:
        host = urlsplit(host).netloc
    host = host.split("@")[ -1 ]
    host = host.split(":")[0]
    if host.startswith("*."):
        host = host[2:]
    return host


def host_in_scope(host: str, scope: str) -> bool:
    host = normalize_hostname(host)
    scope = normalize_hostname(scope)
    return host == scope or host.endswith("." + scope)


def normalize_url(url: str) -> str | None:
    url = ANSI_RE.sub("", url).strip()
    if not url or not url.lower().startswith(("http://", "https://")):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.netloc:
        return None
    scheme = parts.scheme.lower()
    hostname = normalize_hostname(parts.hostname or "")
    if not hostname:
        return None
    port = parts.port
    netloc = hostname
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{hostname}:{port}"
    path = parts.path or "/"
    query = urlencode(parse_qsl(parts.query, keep_blank_values=True), doseq=True)
    return urlunsplit((scheme, netloc, path, query, ""))


def extract_urls_from_text(text: str) -> list[str]:
    results = []
    for match in URL_RE.findall(text):
        normalized = normalize_url(match)
        if normalized:
            results.append(normalized)
    return dedupe_preserve_order(results)


def filename_safe(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("._") or "file"


def http_get(url: str, headers: dict[str, str] | None = None, timeout: int = 20) -> bytes:
    req = Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urlopen(req, timeout=timeout, context=SSL_CONTEXT) as resp:
        return resp.read()


def http_get_json(url: str, headers: dict[str, str] | None = None, timeout: int = 20) -> Any:
    raw = http_get(url, headers=headers, timeout=timeout)
    return json.loads(raw.decode("utf-8", errors="ignore"))


def run_subprocess(
    cmd: Sequence[str],
    logger: JsonLogger,
    timeout: int,
    stdout_path: Path | None = None,
    stdin_path: Path | None = None,
    stage: str = "command",
    allow_fail: bool = True,
) -> subprocess.CompletedProcess[str] | None:
    logger.log("info", "run_command", stage=stage, cmd=list(cmd), timeout=timeout)
    try:
        stdin_handle = stdin_path.open("rb") if stdin_path else None
        stdout_handle = stdout_path.open("w", encoding="utf-8") if stdout_path else subprocess.PIPE
        try:
            completed = subprocess.run(
                list(cmd),
                stdin=stdin_handle,
                stdout=stdout_handle,
                stderr=subprocess.PIPE,
                text=stdout_path is None,
                timeout=timeout,
                check=False,
            )
        finally:
            if stdin_handle:
                stdin_handle.close()
            if stdout_path and hasattr(stdout_handle, "close"):
                stdout_handle.close()
        if isinstance(completed.stderr, bytes):
            stderr_text = completed.stderr.decode("utf-8", errors="ignore")
        else:
            stderr_text = completed.stderr or ""
        if completed.returncode != 0:
            logger.log("warning", "command_nonzero", stage=stage, cmd=list(cmd), returncode=completed.returncode, stderr=stderr_text[-2000:])
            if not allow_fail:
                raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(cmd)}")
        return completed
    except subprocess.TimeoutExpired:
        logger.log("warning", "command_timeout", stage=stage, cmd=list(cmd), timeout=timeout)
        warn(f"{stage} timed out after {timeout}s")
        return None
    except FileNotFoundError:
        logger.log("warning", "command_missing", stage=stage, cmd=list(cmd))
        warn(f"tool not found for stage {stage}: {cmd[0]}")
        return None


def merge_text_files(output: Path, inputs: Sequence[Path]) -> int:
    merged = dedupe_preserve_order(line for path in inputs for line in read_lines(path))
    return write_lines(output, merged)


def is_js_url(url: str) -> bool:
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return False
    return path.endswith(".js")


def is_static_url(url: str) -> bool:
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return False
    for ext in STATIC_EXTENSIONS:
        if path.endswith(ext):
            return True
    return False


def is_sensitive_file_url(url: str) -> bool:
    try:
        path = urlsplit(url).path.lower()
    except ValueError:
        return False
    for ext in sorted(SENSITIVE_FILE_EXTENSIONS, key=len, reverse=True):
        if path.endswith(ext):
            return True
    return False


def should_keep_filtered_url(url: str, scope: str) -> bool:
    normalized = normalize_url(url)
    if not normalized:
        return False
    try:
        parts = urlsplit(normalized)
    except ValueError:
        return False
    if not host_in_scope(parts.hostname or "", scope):
        return False
    if is_js_url(normalized):
        return False
    if is_static_url(normalized):
        return False
    return True


def vt_headers(api_key: str) -> dict[str, str]:
    return {"x-apikey": api_key, "accept": "application/json"}


class MFReconRunner:
    def __init__(self, config: RunConfig, target: str, root: Path, tools: dict[str, ToolInfo]) -> None:
        self.config = config
        self.target = target
        self.paths = OutputPaths.create(root)
        self.logger = JsonLogger(self.paths.logs / "run.jsonl")
        self.state = ResumeState(self.paths.state)
        self.tools = tools
        self.templates_dir = self.detect_templates_dir()
        self.vt_keys = [k.strip() for k in (config.vt_api_key or "").split(",") if k.strip()]
        self._vt_index = 0

    def detect_templates_dir(self) -> Path | None:
        if self.config.skip_nuclei:
            return None
        candidates: list[Path] = []
        if self.config.templates_dir:
            candidates.append(Path(self.config.templates_dir).expanduser().resolve(strict=False))
        candidates.extend(
            [
                (Path.home() / "nuclei-templates").resolve(strict=False),
                (Path.home() / ".local" / "share" / "nuclei-templates").resolve(strict=False),
            ]
        )
        for candidate in candidates:
            if candidate.exists() and candidate.is_dir():
                return candidate
        return None

    def next_vt_key(self) -> str | None:
        if not self.vt_keys:
            return None
        key = self.vt_keys[self._vt_index % len(self.vt_keys)]
        self._vt_index += 1
        return key

    def should_skip(self, stage: str, outputs: Sequence[Path]) -> bool:
        if not self.config.resume:
            return False
        if not self.state.is_done(stage):
            return False
        return all(path.exists() for path in outputs)

    def run(self) -> None:
        info(f"Target: {self.target}")
        info(f"Output: {self.paths.root}")
        if self.templates_dir:
            info(f"Nuclei templates: {self.templates_dir}")
        elif not self.config.skip_nuclei:
            warn("Nuclei templates directory not found; nuclei stages that need templates will be skipped")

        self.enumerate_subdomains()
        self.probe_alive_hosts()
        self.collect_urls()
        self.run_dirsearch()
        self.merge_url_corpus()
        self.extract_js_urls()
        self.filter_urls()
        self.extract_params()
        self.verify_alive_params()
        self.run_nuclei_stages()
        self.download_js_files()
        self.run_js_file_nuclei()
        self.write_ai_handoff()
        self.export_root_aliases()
        self.write_summary()

    def enumerate_subdomains(self) -> None:
        stage_name = "subdomains"
        outputs = [self.paths.subs / "all_subdomains.txt"]
        if self.should_skip(stage_name, outputs):
            info("Skipping subdomain enumeration because resume state says it is done")
            return
        step("Subdomain enumeration")
        self.state.mark_started(stage_name)

        source_files = {
            "subfinder": self.paths.subs / "subfinder.txt",
            "assetfinder": self.paths.subs / "assetfinder.txt",
            "amass": self.paths.subs / "amass_passive.txt",
            "crtsh": self.paths.subs / "crtsh.txt",
            "wayback_hosts": self.paths.subs / "wayback_hosts.txt",
            "virustotal": self.paths.subs / "virustotal.txt",
        }

        def do_subfinder() -> None:
            path = source_files["subfinder"]
            tool = self.tools["subfinder"].path
            assert tool
            run_subprocess([tool, "-d", self.target, "-silent", "-o", str(path)], self.logger, timeout=300, stage="subfinder")
            self.clean_subdomain_file(path)

        def do_assetfinder() -> None:
            path = source_files["assetfinder"]
            tool = self.tools["assetfinder"].path
            if not tool:
                write_lines(path, [])
                return
            completed = run_subprocess([tool, "--subs-only", self.target], self.logger, timeout=180, stage="assetfinder")
            lines = []
            if completed and completed.stdout:
                lines = completed.stdout.splitlines()
            self.write_clean_subdomain_file(path, lines)

        def do_amass() -> None:
            path = source_files["amass"]
            tool = self.tools["amass"].path
            if not tool:
                write_lines(path, [])
                return
            run_subprocess(
                [
                    tool,
                    "enum",
                    "-passive",
                    "-nocolor",
                    "-timeout",
                    "5",
                    "-d",
                    self.target,
                ],
                self.logger,
                timeout=360,
                stage="amass_enum",
            )
            completed = run_subprocess(
                [
                    tool,
                    "subs",
                    "-names",
                    "-nocolor",
                    "-d",
                    self.target,
                ],
                self.logger,
                timeout=60,
                stage="amass_subs",
            )
            lines = completed.stdout.splitlines() if completed and completed.stdout else []
            self.write_clean_subdomain_file(path, lines)

        def do_crtsh() -> None:
            path = source_files["crtsh"]
            url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            rows: list[str] = []
            try:
                data = http_get_json(url, timeout=self.config.timeout)
                if isinstance(data, list):
                    for row in data:
                        value = str(row.get("name_value", "")).replace("\r", "")
                        for item in value.splitlines():
                            if item:
                                rows.append(item)
            except Exception as exc:
                self.logger.log("warning", "crtsh_failed", target=self.target, error=str(exc))
                warn(f"crt.sh failed: {exc}")
            self.write_clean_subdomain_file(path, rows)

        def do_wayback_hosts() -> None:
            path = source_files["wayback_hosts"]
            rows = self.wayback_host_query(self.target)
            self.write_clean_subdomain_file(path, rows)

        def do_virustotal() -> None:
            path = source_files["virustotal"]
            if not self.vt_keys:
                write_lines(path, [])
                return
            subdomains = self.virustotal_collect_subdomains(self.target)
            self.write_clean_subdomain_file(path, subdomains)

        jobs = {
            "subfinder": do_subfinder,
            "assetfinder": do_assetfinder,
            "amass": do_amass,
            "crtsh": do_crtsh,
            "wayback_hosts": do_wayback_hosts,
            "virustotal": do_virustotal,
        }

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(func): name for name, func in jobs.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    future.result()
                    count = sum(1 for _ in read_lines(source_files[name]))
                    info(f"{name}: {count}")
                except Exception as exc:
                    self.logger.log("warning", "source_failed", source=name, error=str(exc))
                    warn(f"{name} failed: {exc}")
                    write_lines(source_files[name], [])

        merge_text_files(self.paths.subs / "all_subdomains.txt", list(source_files.values()))
        total = sum(1 for _ in read_lines(self.paths.subs / "all_subdomains.txt"))
        info(f"all_subdomains: {total}")
        self.state.mark_done(stage_name, count=total)

    def clean_subdomain_file(self, path: Path) -> None:
        self.write_clean_subdomain_file(path, list(read_lines(path)))

    def write_clean_subdomain_file(self, path: Path, lines: Iterable[str]) -> None:
        cleaned = []
        for line in lines:
            host = normalize_hostname(line)
            if host and host_in_scope(host, self.target):
                cleaned.append(host)
        write_lines(path, dedupe_preserve_order(cleaned))

    def wayback_host_query(self, domain: str) -> list[str]:
        endpoint = "https://web.archive.org/cdx/search/cdx"
        params = urlencode({
            "url": f"*.{domain}/*",
            "output": "text",
            "fl": "original",
            "collapse": "urlkey",
        })
        url = f"{endpoint}?{params}"
        hosts: list[str] = []
        try:
            data = http_get(url, timeout=max(20, self.config.timeout + 10)).decode("utf-8", errors="ignore")
            for line in data.splitlines():
                normalized = normalize_url(line.strip())
                if not normalized:
                    continue
                host = normalize_hostname(urlsplit(normalized).hostname or "")
                if host_in_scope(host, domain):
                    hosts.append(host)
        except Exception as exc:
            self.logger.log("warning", "wayback_hosts_failed", target=domain, error=str(exc))
            warn(f"Wayback host collection failed: {exc}")
        return dedupe_preserve_order(hosts)

    def wayback_url_query(
        self,
        domain: str,
        include_subdomains: bool = True,
        extensions_only: bool = False,
        include_status: str | None = None,
        exclude_status: str | None = None,
    ) -> list[str]:
        base_url = "https://web.archive.org/cdx/search/cdx"
        query = {
            "url": f"*.{domain}/*" if include_subdomains else f"{domain}/*",
            "collapse": "urlkey",
            "output": "text",
            "fl": "original,statuscode",
        }
        url = f"{base_url}?{urlencode(query)}"
        filters: list[str] = []
        if extensions_only:
            ext_parts = [re.escape(ext.lstrip(".")) for ext in sorted(SENSITIVE_FILE_EXTENSIONS, key=len, reverse=True)]
            ext_regex = "|".join(part.replace("\\\\", "\\") for part in ext_parts)
            filters.append(f"original:.*\\.({ext_regex})$")
        if include_status:
            filters.append(f"statuscode:({include_status.replace(',', '|')})")
        if exclude_status:
            filters.append(f"!statuscode:({exclude_status.replace(',', '|')})")
        for item in filters:
            url += "&" + urlencode({"filter": item})

        results: list[str] = []
        try:
            data = http_get(url, timeout=max(20, self.config.timeout + 10)).decode("utf-8", errors="ignore")
            for line in data.splitlines():
                first = line.split()[0].strip() if line.strip() else ""
                normalized = normalize_url(first)
                if normalized:
                    results.append(normalized)
        except Exception as exc:
            self.logger.log("warning", "wayback_urls_failed", target=domain, error=str(exc))
            warn(f"Wayback URL collection failed: {exc}")
        return dedupe_preserve_order(results)

    def virustotal_collect_subdomains(self, domain: str) -> list[str]:
        key = self.next_vt_key()
        if not key:
            return []
        headers = vt_headers(key)
        report_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        try:
            report = http_get_json(report_url, headers=headers, timeout=self.config.timeout)
            (self.paths.vt / "domain_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        except HTTPError as exc:
            self.logger.log("warning", "vt_domain_report_failed", status=exc.code, target=domain)
            warn(f"VirusTotal domain report failed with HTTP {exc.code}")
        except Exception as exc:
            self.logger.log("warning", "vt_domain_report_failed", target=domain, error=str(exc))
            warn(f"VirusTotal domain report failed: {exc}")

        results: list[str] = []
        for relationship in VT_DOMAIN_RELATIONSHIP_PATHS:
            key = self.next_vt_key()
            if not key:
                break
            rel_headers = vt_headers(key)
            rel_url = f"https://www.virustotal.com/api/v3/domains/{domain}/{relationship}?limit={self.config.vt_limit}"
            try:
                payload = http_get_json(rel_url, headers=rel_headers, timeout=self.config.timeout)
                (self.paths.vt / f"{relationship}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
                data = payload.get("data", []) if isinstance(payload, dict) else []
                if relationship == "subdomains":
                    for item in data:
                        value = normalize_hostname(str(item.get("id", "")))
                        if value and host_in_scope(value, domain):
                            results.append(value)
                elif relationship == "resolutions":
                    res_lines = []
                    for item in data:
                        attrs = item.get("attributes", {}) if isinstance(item, dict) else {}
                        host = normalize_hostname(str(attrs.get("host_name", "")))
                        ip = str(attrs.get("ip_address", "")).strip()
                        if host:
                            res_lines.append(f"{host} {ip}".strip())
                    write_lines(self.paths.vt / "resolutions.txt", dedupe_preserve_order(res_lines))
            except HTTPError as exc:
                self.logger.log("warning", "vt_relationship_failed", target=domain, relationship=relationship, status=exc.code)
                warn(f"VirusTotal {relationship} failed with HTTP {exc.code}")
            except Exception as exc:
                self.logger.log("warning", "vt_relationship_failed", target=domain, relationship=relationship, error=str(exc))
                warn(f"VirusTotal {relationship} failed: {exc}")
        return dedupe_preserve_order(results)

    def probe_alive_hosts(self) -> None:
        stage_name = "alive_hosts"
        outputs = [self.paths.alive / "alive_subdomains.txt", self.paths.alive / "httpx.jsonl"]
        if self.should_skip(stage_name, outputs):
            info("Skipping alive-host probe because resume state says it is done")
            return
        step("Live host detection with httpx")
        self.state.mark_started(stage_name)

        input_file = self.paths.subs / "all_subdomains.txt"
        if not input_file.exists() or input_file.stat().st_size == 0:
            write_lines(self.paths.alive / "httpx.jsonl", [])
            write_lines(self.paths.alive / "alive_subdomains.txt", [])
            self.state.mark_done(stage_name, count=0)
            return

        tool = self.tools["httpx"].path
        assert tool
        run_subprocess(
            [
                tool,
                "-l", str(input_file),
                "-title",
                "-sc",
                "-fr",
                "-j",
                "-o", str(self.paths.alive / "httpx.jsonl"),
                "-t", str(self.config.threads),
                "-rl", str(self.config.rate_limit),
                "-timeout", str(self.config.timeout),
                "-retries", "1",
                "-ports", "80,443,8080,8443",
            ],
            self.logger,
            timeout=max(300, self.config.timeout * 20),
            stage="httpx_hosts",
        )

        all_alive: list[str] = []
        keep_urls: list[str] = []
        url_collect: list[str] = []
        not_found: list[str] = []
        human_rows: list[str] = []
        gau_hosts: list[str] = []

        httpx_json = self.paths.alive / "httpx.jsonl"
        if httpx_json.exists():
            with httpx_json.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    url = normalize_url(str(row.get("url") or row.get("input") or ""))
                    if not url:
                        continue
                    status = int(row.get("status_code") or 0)
                    title = str(row.get("title") or "").strip().replace("\n", " ")
                    all_alive.append(url)
                    human_rows.append(f"{url} [{status}] {title}".strip())
                    if status in {200, 301, 302, 403}:
                        keep_urls.append(url)
                    if status in {200, 301, 302}:
                        url_collect.append(url)
                        host = normalize_hostname(urlsplit(url).hostname or "")
                        if host:
                            gau_hosts.append(host)
                    if status == 404:
                        not_found.append(url)

        write_lines(self.paths.alive / "live-subs.txt", dedupe_preserve_order(human_rows))
        write_lines(self.paths.alive / "alive_subdomains.txt", dedupe_preserve_order(all_alive))
        write_lines(self.paths.alive / "live-subs-200-301-302-403.txt", dedupe_preserve_order(keep_urls))
        write_lines(self.paths.alive / "live-subs-url-collect.txt", dedupe_preserve_order(url_collect))
        write_lines(self.paths.alive / "live-subs-404.txt", dedupe_preserve_order(not_found))
        write_lines(self.paths.alive / "gau-input-hosts.txt", dedupe_preserve_order(gau_hosts))
        info(f"alive_subdomains: {len(dedupe_preserve_order(all_alive))}")
        self.state.mark_done(stage_name, count=len(dedupe_preserve_order(all_alive)))

    def collect_urls(self) -> None:
        stage_name = "url_sources"
        outputs = [self.paths.urls / "wayback.txt", self.paths.urls / "gau.txt", self.paths.urls / "katana_urls.txt"]
        if self.should_skip(stage_name, outputs):
            info("Skipping URL source collection because resume state says it is done")
            return
        step("URL collection")
        self.state.mark_started(stage_name)

        files = {
            "wayback": self.paths.urls / "wayback.txt",
            "wayback_sensitive": self.paths.urls / "wayback_sensitive.txt",
            "gau": self.paths.urls / "gau.txt",
            "katana": self.paths.urls / "katana_urls.txt",
        }

        def do_wayback() -> None:
            write_lines(files["wayback"], self.wayback_url_query(self.target, include_subdomains=True))
            write_lines(files["wayback_sensitive"], self.wayback_url_query(self.target, include_subdomains=True, extensions_only=True))

        def do_gau() -> None:
            input_file = self.paths.alive / "gau-input-hosts.txt"
            if not input_file.exists() or input_file.stat().st_size == 0:
                write_lines(files["gau"], [])
                return
            tool = self.tools["gau"].path
            assert tool
            completed = run_subprocess(
                [tool, "--subs", "--threads", str(min(50, self.config.threads)), "--timeout", str(self.config.timeout * 3)],
                self.logger,
                timeout=max(300, self.config.timeout * 20),
                stdin_path=input_file,
                stage="gau",
            )
            urls: list[str] = []
            if completed and completed.stdout:
                urls = [normalize_url(line) for line in completed.stdout.splitlines()]
            write_lines(files["gau"], dedupe_preserve_order([u for u in urls if u]))

        def do_katana() -> None:
            input_file = self.paths.alive / "live-subs-url-collect.txt"
            if not input_file.exists() or input_file.stat().st_size == 0:
                write_lines(files["katana"], [])
                return
            tool = self.tools["katana"].path
            assert tool
            completed = run_subprocess(
                [
                    tool,
                    "-silent",
                    "-jc",
                    "-d", str(self.config.katana_depth),
                    "-c", str(min(10, self.config.threads)),
                    "-p", str(min(10, max(2, self.config.threads // 5))),
                    "-rl", str(self.config.rate_limit),
                    "-kf", "robotstxt,sitemapxml",
                    "-fsu",
                ],
                self.logger,
                timeout=max(300, self.config.timeout * 30),
                stdin_path=input_file,
                stage="katana",
            )
            urls: list[str] = []
            if completed and completed.stdout:
                urls = [normalize_url(line) for line in completed.stdout.splitlines()]
            write_lines(files["katana"], dedupe_preserve_order([u for u in urls if u]))

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(do_wayback): "wayback",
                executor.submit(do_gau): "gau",
                executor.submit(do_katana): "katana",
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    self.logger.log("warning", "url_source_failed", source=name, error=str(exc))
                    warn(f"{name} failed: {exc}")
        self.state.mark_done(stage_name)

    def run_dirsearch(self) -> None:
        stage_name = "dirsearch"
        outputs = [self.paths.urls / "dirsearch_urls.txt"]
        if self.config.skip_dirsearch:
            write_lines(self.paths.urls / "dirsearch_urls.txt", [])
            return
        if self.should_skip(stage_name, outputs):
            info("Skipping dirsearch because resume state says it is done")
            return
        step("Directory discovery with dirsearch")
        self.state.mark_started(stage_name)

        tool_path = self.tools["dirsearch"].path
        input_file = self.paths.alive / "live-subs-200-301-302-403.txt"
        if not tool_path:
            warn("dirsearch not found; skipping this stage")
            write_lines(self.paths.urls / "dirsearch_urls.txt", [])
            self.state.mark_done(stage_name, skipped=True)
            return
        if not input_file.exists() or input_file.stat().st_size == 0:
            write_lines(self.paths.urls / "dirsearch_urls.txt", [])
            self.state.mark_done(stage_name, count=0)
            return

        if tool_path.endswith("dirsearch.py"):
            cmd = [sys.executable, tool_path]
        else:
            cmd = [tool_path]

        cmd += [
            "-l", str(input_file),
            "-t", str(min(30, self.config.threads)),
            "--full-url",
            "--format", "plain",
            "--no-color",
            "--follow-redirects",
            "-q",
            "-i", "200-399,401,403",
            "--max-rate", str(self.config.rate_limit),
            "--retries", "1",
            "-o", str(self.paths.urls / "dirsearch_report.txt"),
        ]
        if self.config.dirsearch_wordlist:
            cmd += ["-w", str(Path(self.config.dirsearch_wordlist).expanduser())]
        if self.config.dirsearch_extensions:
            cmd += ["-e", self.config.dirsearch_extensions]

        run_subprocess(cmd, self.logger, timeout=max(600, self.config.timeout * 40), stage="dirsearch")
        report_text = ""
        report_file = self.paths.urls / "dirsearch_report.txt"
        if report_file.exists():
            report_text = report_file.read_text(encoding="utf-8", errors="ignore")
        urls = extract_urls_from_text(report_text)
        write_lines(self.paths.urls / "dirsearch_urls.txt", urls)
        info(f"dirsearch_urls: {len(urls)}")
        self.state.mark_done(stage_name, count=len(urls))

    def merge_url_corpus(self) -> None:
        stage_name = "merge_urls"
        outputs = [self.paths.urls / "all_urls.txt"]
        if self.should_skip(stage_name, outputs):
            info("Skipping URL merge because resume state says it is done")
            return
        step("Merge URL corpus")
        self.state.mark_started(stage_name)
        sources = [
            self.paths.urls / "wayback.txt",
            self.paths.urls / "wayback_sensitive.txt",
            self.paths.urls / "gau.txt",
            self.paths.urls / "katana_urls.txt",
            self.paths.urls / "dirsearch_urls.txt",
        ]
        merged = dedupe_preserve_order(
            normalize_url(line)
            for path in sources
            for line in read_lines(path)
        )
        merged = [u for u in merged if u]
        write_lines(self.paths.urls / "all_urls.txt", merged)
        info(f"all_urls: {len(merged)}")
        self.state.mark_done(stage_name, count=len(merged))

    def extract_js_urls(self) -> None:
        stage_name = "js_urls"
        outputs = [self.paths.js / "js-urls.txt", self.paths.js / "js-urls-selected.txt"]
        if self.should_skip(stage_name, outputs):
            info("Skipping JS URL extraction because resume state says it is done")
            return
        step("Extract JavaScript URLs")
        self.state.mark_started(stage_name)
        all_urls = [line for line in read_lines(self.paths.urls / "all_urls.txt")]
        js_urls = [line for line in all_urls if is_js_url(line)]
        js_urls = dedupe_preserve_order(js_urls)
        write_lines(self.paths.js / "js-urls.txt", js_urls)

        if self.config.js_mode == "off":
            selected: list[str] = []
        elif self.config.js_mode == "all":
            selected = js_urls
        else:
            selected = self.select_important_js_urls(js_urls)
            if not selected:
                selected = js_urls
        write_lines(self.paths.js / "js-urls-selected.txt", selected)
        info(f"js_urls_total: {len(js_urls)}")
        info(f"js_urls_selected: {len(selected)}")
        self.state.mark_done(stage_name, total=len(js_urls), selected=len(selected))

    def select_important_js_urls(self, urls: Sequence[str]) -> list[str]:
        per_host: dict[str, int] = {}
        selected: list[str] = []
        for url in urls:
            parts = urlsplit(url)
            host = normalize_hostname(parts.hostname or "")
            file_name = Path(parts.path).name.lower()
            path_l = parts.path.lower()
            if JS_LOCALE_RE.fullmatch(file_name):
                continue
            if JS_TRACKER_RE.fullmatch(file_name):
                continue
            important = bool(JS_IMPORTANT_FILE_RE.search(file_name) or JS_IMPORTANT_PATH_RE.search(path_l))
            if not important:
                continue
            if per_host.get(host, 0) >= self.config.max_js_per_host:
                continue
            per_host[host] = per_host.get(host, 0) + 1
            selected.append(url)
        return dedupe_preserve_order(selected)

    def filter_urls(self) -> None:
        stage_name = "filter_urls"
        outputs = [self.paths.urls / "filtered_urls.txt"]
        if self.should_skip(stage_name, outputs):
            info("Skipping URL filtering because resume state says it is done")
            return
        step("Filter URLs")
        self.state.mark_started(stage_name)

        all_urls = [line for line in read_lines(self.paths.urls / "all_urls.txt")]
        filtered = [url for url in all_urls if should_keep_filtered_url(url, self.target)]
        filtered = dedupe_preserve_order(filtered)
        interesting = [url for url in filtered if INTERESTING_URL_RE.search(url)]
        api_urls = [url for url in filtered if API_URL_RE.search(url)]
        sensitive_files = [url for url in all_urls if host_in_scope(urlsplit(url).hostname or "", self.target) and is_sensitive_file_url(url)]

        write_lines(self.paths.urls / "filtered_urls.txt", filtered)
        write_lines(self.paths.urls / "interesting.txt", dedupe_preserve_order(interesting))
        write_lines(self.paths.urls / "api.txt", dedupe_preserve_order(api_urls))
        write_lines(self.paths.urls / "sensitive_files.txt", dedupe_preserve_order(sensitive_files))
        info(f"filtered_urls: {len(filtered)}")
        self.state.mark_done(stage_name, count=len(filtered))

    def extract_params(self) -> None:
        stage_name = "params"
        outputs = [self.paths.urls / "params.txt"]
        if self.should_skip(stage_name, outputs):
            info("Skipping parameter extraction because resume state says it is done")
            return
        step("Parameter extraction")
        self.state.mark_started(stage_name)
        params = []
        for url in read_lines(self.paths.urls / "filtered_urls.txt"):
            try:
                if urlsplit(url).query and "=" in urlsplit(url).query:
                    params.append(url)
            except ValueError:
                continue
        params = dedupe_preserve_order(params)
        write_lines(self.paths.urls / "params.txt", params)
        info(f"params: {len(params)}")
        self.state.mark_done(stage_name, count=len(params))

    def verify_alive_params(self) -> None:
        stage_name = "alive_params"
        outputs = [self.paths.alive / "alive_params.txt"]
        if self.should_skip(stage_name, outputs):
            info("Skipping alive param verification because resume state says it is done")
            return
        step("Verify alive parameter URLs")
        self.state.mark_started(stage_name)

        input_file = self.paths.urls / "params.txt"
        if not input_file.exists() or input_file.stat().st_size == 0:
            write_lines(self.paths.alive / "alive_params.txt", [])
            self.state.mark_done(stage_name, count=0)
            return

        tool = self.tools["httpx"].path
        assert tool
        run_subprocess(
            [
                tool,
                "-l", str(input_file),
                "-sc",
                "-fr",
                "-j",
                "-o", str(self.paths.alive / "params_httpx.jsonl"),
                "-t", str(self.config.threads),
                "-rl", str(self.config.rate_limit),
                "-timeout", str(self.config.timeout),
                "-retries", "1",
            ],
            self.logger,
            timeout=max(300, self.config.timeout * 20),
            stage="httpx_params",
        )

        alive_params: list[str] = []
        with (self.paths.alive / "params_httpx.jsonl").open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                status = int(row.get("status_code") or 0)
                url = normalize_url(str(row.get("url") or row.get("input") or ""))
                if url and status in {200, 301, 302, 403}:
                    alive_params.append(url)
        alive_params = dedupe_preserve_order(alive_params)
        write_lines(self.paths.alive / "alive_params.txt", alive_params)
        info(f"alive_params: {len(alive_params)}")
        self.state.mark_done(stage_name, count=len(alive_params))

    def run_nuclei_stages(self) -> None:
        if self.config.skip_nuclei:
            return
        if not self.tools["nuclei"].path:
            warn("nuclei not found; skipping nuclei stages")
            return
        if not self.templates_dir:
            warn("nuclei templates dir not found; skipping nuclei stages")
            return
        stage_name = "nuclei"
        outputs = [self.paths.nuclei / "findings.jsonl", self.paths.nuclei / "findings.csv", self.paths.nuclei / "findings.json"]
        if self.should_skip(stage_name, outputs):
            info("Skipping nuclei because resume state says it is done")
            return
        step("Nuclei stages")
        self.state.mark_started(stage_name)
        project_path = self.paths.project
        stage_outputs: list[Path] = []
        
        live_hosts = self.paths.alive / "live-subs-200-301-302-403.txt"
        not_found = self.paths.alive / "live-subs-404.txt"
        url_targets = self.paths.nuclei / "url-targets.txt"
        url_targets_data = dedupe_preserve_order([*read_lines(self.paths.urls / "interesting.txt"), *read_lines(self.paths.urls / "api.txt")])
        write_lines(url_targets, url_targets_data)
        alive_params = self.paths.alive / "alive_params.txt"

        kev_profile = self.templates_dir / "profiles" / "kev.yml"
        misconfig_profile = self.templates_dir / "profiles" / "misconfigurations.yml"
        takeover_profile = self.templates_dir / "profiles" / "subdomain-takeovers.yml"
        wordpress_profile = self.templates_dir / "profiles" / "wordpress.yml"

        if live_hosts.exists() and live_hosts.stat().st_size and kev_profile.exists():
            stage_outputs.append(self.run_nuclei_list_stage("hosts-kev", live_hosts, ["-tp", str(kev_profile)]))
        if live_hosts.exists() and live_hosts.stat().st_size and misconfig_profile.exists():
            stage_outputs.append(self.run_nuclei_list_stage("hosts-misconfig", live_hosts, ["-tp", str(misconfig_profile)]))
        if not_found.exists() and not_found.stat().st_size:
            if takeover_profile.exists():
                stage_outputs.append(self.run_nuclei_list_stage("hosts-takeovers", not_found, ["-tp", str(takeover_profile)]))
            elif (self.templates_dir / "http" / "takeovers").exists():
                stage_outputs.append(self.run_nuclei_list_stage("hosts-takeovers", not_found, ["-t", str(self.templates_dir / "http" / "takeovers")]))

        if url_targets.exists() and url_targets.stat().st_size:
            template_args: list[str] = []
            for rel in ["http/exposed-panels", "http/exposures", "http/misconfiguration"]:
                path = self.templates_dir / rel
                if path.exists():
                    template_args += ["-t", str(path)]
            if template_args:
                template_args += ["-s", "low,medium,high,critical"]
                stage_outputs.append(self.run_nuclei_list_stage("urls-surface", url_targets, template_args))

        if alive_params.exists() and alive_params.stat().st_size:
            template_args = []
            for rel in ["http/vulnerabilities", "http/exposures", "http/misconfiguration"]:
                path = self.templates_dir / rel
                if path.exists():
                    template_args += ["-t", str(path)]
            if template_args:
                template_args += ["-s", self.config.severity]
                stage_outputs.append(self.run_nuclei_list_stage("params-scan", alive_params, template_args))

        wp_hit = False
        wordpress_re = re.compile(r"wp-content|wp-includes|wp-json|/wp-admin|wordpress", re.I)
        for path in [self.paths.urls / "all_urls.txt", self.paths.alive / "live-subs.txt"]:
            if path.exists() and wordpress_re.search(path.read_text(encoding="utf-8", errors="ignore")):
                wp_hit = True
                break
        if wp_hit and live_hosts.exists() and live_hosts.stat().st_size and wordpress_profile.exists():
            stage_outputs.append(self.run_nuclei_list_stage("hosts-wordpress", live_hosts, ["-tp", str(wordpress_profile)]))

        self.aggregate_nuclei_findings()
        count = sum(1 for _ in read_lines(self.paths.nuclei / "findings.jsonl"))
        info(f"nuclei_findings: {count}")
        self.state.mark_done(stage_name, count=count)

    def run_nuclei_list_stage(
        self,
        stage: str,
        target_file: Path,
        template_args: list[str],
        output_basename: str | None = None,
    ) -> Path:
        tool = self.tools["nuclei"].path
        assert tool
        basename = output_basename or stage
        text_file = self.paths.nuclei / f"{basename}.txt"
        jsonl_file = self.paths.nuclei / f"{basename}.jsonl"
        cmd = [
            tool,
            "-l", str(target_file),
            "-o", str(text_file),
            "-jle", str(jsonl_file),
            "-rl", str(self.config.nuclei_rate_limit),
            "-bs", str(self.config.nuclei_bulk_size),
            "-c", str(self.config.nuclei_concurrency),
            "-timeout", str(self.config.timeout),
            "-retries", "1",
            "-fr",
            "-project",
            "-project-path", str(self.paths.project),
            "-or",
            "-nc",
            "-silent",
            "-ept", "headless",
            *template_args,
        ]
        run_subprocess(cmd, self.logger, timeout=max(900, self.config.timeout * 60), stage=f"nuclei_{stage}")
        if not jsonl_file.exists():
            write_lines(jsonl_file, [])
        return jsonl_file

    def prepare_js_nuclei_templates(self) -> Path:
        tpl_dir = self.paths.nuclei / "custom-templates" / "js"
        tpl_dir.mkdir(parents=True, exist_ok=True)
        templates = {
            "js-endpoints.yaml": """id: js-endpoint-hints\n\ninfo:\n  name: JavaScript Endpoint Hints\n  author: mfrecon\n  severity: info\n  description: Extract likely API, GraphQL, WebSocket and route hints from local JavaScript files.\n  tags: file,js,endpoint,graphql,websocket\n\nfile:\n  - extensions:\n      - js\n\n    matchers:\n      - type: regex\n        regex:\n          - \"(?i)(https?://|wss?://|/api/|graphql|websocket|/v[0-9]+/)\"\n\n    extractors:\n      - type: regex\n        name: endpoint\n        regex:\n          - \"(?i)(https?://[^\\s\\\"<>]+|wss?://[^\\s\\\"<>]+|/[A-Za-z0-9._~!$&()*+,;=:@%/-]{4,})\"\n""",
            "js-secrets.yaml": """id: js-secret-patterns\n\ninfo:\n  name: JavaScript Secret Patterns\n  author: mfrecon\n  severity: medium\n  description: Extract common secret and token patterns from local JavaScript files.\n  tags: file,js,secrets,tokens\n\nfile:\n  - extensions:\n      - js\n\n    matchers:\n      - type: regex\n        regex:\n          - \"(AIza[0-9A-Za-z\\-_]{35}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9._-]{10,}\\.[A-Za-z0-9._-]{10,}|(?i)(api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|authorization)\\\"?\\s*[:=]\\s*\\\"[^\\\"]{8,}\\\")\"\n\n    extractors:\n      - type: regex\n        name: secret\n        regex:\n          - \"(AIza[0-9A-Za-z\\-_]{35}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9._-]{10,}\\.[A-Za-z0-9._-]{10,}|(?i)(api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|authorization)\\\"?\\s*[:=]\\s*\\\"[^\\\"]{8,}\\\")\"\n""",
            "js-auth-surface.yaml": """id: js-auth-admin-surface\n\ninfo:\n  name: JavaScript Auth and Admin Surface\n  author: mfrecon\n  severity: info\n  description: Flag local JavaScript files containing likely auth, admin, role, payment, or upload logic.\n  tags: file,js,auth,admin,payment,upload\n\nfile:\n  - extensions:\n      - js\n\n    matchers:\n      - type: regex\n        regex:\n          - \"(?i)(admin|auth|oauth|sso|otp|session|bearer|graphql|payment|invoice|upload|document|passport|verify|role|permission)\"\n\n    extractors:\n      - type: regex\n        name: keyword\n        regex:\n          - \"(?i)(admin|auth|oauth|sso|otp|session|bearer|graphql|payment|invoice|upload|document|passport|verify|role|permission)\"\n""",
        }
        for name, content in templates.items():
            (tpl_dir / name).write_text(content, encoding="utf-8")
        return tpl_dir

    def download_js_files(self) -> None:
        stage_name = "js_download"
        outputs = [self.paths.js_downloaded]
        if self.config.js_mode == "off" or self.config.skip_js_download:
            return
        if self.should_skip(stage_name, outputs):
            info("Skipping JS downloads because resume state says it is done")
            return
        step("Download selected JavaScript files")
        self.state.mark_started(stage_name)
        urls = list(read_lines(self.paths.js / "js-urls-selected.txt"))
        if not urls:
            self.state.mark_done(stage_name, count=0)
            return

        index_rows: list[dict[str, str]] = []
        errors = 0

        def fetch(url: str) -> dict[str, str] | None:
            if STOP_EVENT.is_set():
                return None
            try:
                parts = urlsplit(url)
                host = filename_safe(normalize_hostname(parts.hostname or "host"))
                host_dir = self.paths.js_downloaded / host
                host_dir.mkdir(parents=True, exist_ok=True)
                name = Path(parts.path).name or "script.js"
                name = filename_safe(name)
                if not name.lower().endswith(".js"):
                    name += ".js"
                dest = host_dir / name
                if dest.exists():
                    stem, suffix = dest.stem, dest.suffix
                    dest = host_dir / f"{stem}-{abs(hash(url)) % 100000}{suffix}"
                data = http_get(url, timeout=max(15, self.config.timeout))
                dest.write_bytes(data)
                return {"url": url, "local_path": str(dest)}
            except Exception as exc:
                self.logger.log("warning", "js_download_failed", url=url, error=str(exc))
                return None

        with ThreadPoolExecutor(max_workers=min(10, max(2, self.config.threads // 5))) as executor:
            future_map = {executor.submit(fetch, url): url for url in urls}
            for future in as_completed(future_map):
                result = future.result()
                if result:
                    index_rows.append(result)
                else:
                    errors += 1

        index_file = self.paths.js / "download-index.csv"
        with index_file.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["url", "local_path"])
            writer.writeheader()
            for row in index_rows:
                writer.writerow(row)
        info(f"js_downloaded: {len(index_rows)} (failed: {errors})")
        self.state.mark_done(stage_name, count=len(index_rows), failed=errors)

    def run_js_file_nuclei(self) -> None:
        if self.config.skip_nuclei:
            return
        if not self.tools["nuclei"].path or not self.templates_dir:
            return
        stage_name = "js_nuclei"
        outputs = [self.paths.nuclei / "js-local.jsonl"]
        if self.should_skip(stage_name, outputs):
            info("Skipping JS file nuclei because resume state says it is done")
            return
        step("Run nuclei against downloaded JavaScript files")
        self.state.mark_started(stage_name)
        js_files = list(self.paths.js_downloaded.rglob("*.js"))
        if not js_files:
            write_lines(self.paths.nuclei / "js-local.jsonl", [])
            self.state.mark_done(stage_name, count=0)
            return
        tool = self.tools["nuclei"].path
        assert tool
        custom_dir = self.prepare_js_nuclei_templates()
        cmd = [
            tool,
            "-file",
            "-target", str(self.paths.js_downloaded),
            "-o", str(self.paths.nuclei / "js-local.txt"),
            "-jle", str(self.paths.nuclei / "js-local.jsonl"),
            "-c", str(self.config.nuclei_concurrency),
            "-timeout", str(self.config.timeout),
            "-project",
            "-project-path", str(self.paths.project),
            "-or",
            "-nc",
            "-silent",
            "-sml",
            "-t", str(custom_dir),
        ]
        extra_custom = self.templates_dir / "custom-js"
        if extra_custom.exists():
            cmd += ["-t", str(extra_custom)]
        run_subprocess(cmd, self.logger, timeout=max(600, self.config.timeout * 40), stage="nuclei_js")
        self.aggregate_nuclei_findings()
        count = sum(1 for _ in read_lines(self.paths.nuclei / "js-local.jsonl"))
        info(f"js_local_nuclei_findings: {count}")
        self.state.mark_done(stage_name, count=count)

    def aggregate_nuclei_findings(self) -> None:
        jsonl_files = sorted(p for p in self.paths.nuclei.glob("*.jsonl") if p.name != "findings.jsonl")
        aggregate_rows: list[dict[str, Any]] = []
        seen_keys: set[tuple[str, str, str]] = set()
        for path in jsonl_files:
            stage = path.stem
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    template_id = str(row.get("template-id") or row.get("templateID") or "")
                    matched_at = str(row.get("matched-at") or row.get("host") or row.get("matched") or "")
                    matcher_name = str(row.get("matcher-name") or "")
                    key = (template_id, matched_at, matcher_name)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    row["stage"] = stage
                    aggregate_rows.append(row)

        jsonl_output = self.paths.nuclei / "findings.jsonl"
        with jsonl_output.open("w", encoding="utf-8") as fh:
            for row in aggregate_rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")

        json_output = self.paths.nuclei / "findings.json"
        json_output.write_text(json.dumps(aggregate_rows, indent=2), encoding="utf-8")

        csv_output = self.paths.nuclei / "findings.csv"
        with csv_output.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=[
                    "stage",
                    "severity",
                    "template_id",
                    "name",
                    "matched_at",
                    "host",
                    "type",
                    "matcher_name",
                    "extracted_results",
                ],
            )
            writer.writeheader()
            for row in aggregate_rows:
                info_block = row.get("info", {}) if isinstance(row.get("info"), dict) else {}
                writer.writerow(
                    {
                        "stage": row.get("stage", ""),
                        "severity": info_block.get("severity", "unknown"),
                        "template_id": row.get("template-id") or row.get("templateID") or "",
                        "name": info_block.get("name", ""),
                        "matched_at": row.get("matched-at") or row.get("matched") or row.get("host") or "",
                        "host": row.get("host", ""),
                        "type": row.get("type") or row.get("protocol") or "",
                        "matcher_name": row.get("matcher-name") or "",
                        "extracted_results": "; ".join(row.get("extracted-results") or []),
                    }
                )

        text_parts: list[str] = []
        for text_file in sorted(self.paths.nuclei.glob("*.txt")):
            if text_file.name == "findings.txt":
                continue
            content = text_file.read_text(encoding="utf-8", errors="ignore").strip()
            if content:
                text_parts.append(content)
        (self.paths.nuclei / "findings.txt").write_text("\n".join(text_parts), encoding="utf-8")

        severity_summary: dict[str, int] = {}
        for row in aggregate_rows:
            info_block = row.get("info", {}) if isinstance(row.get("info"), dict) else {}
            severity = str(info_block.get("severity") or "unknown")
            severity_summary[severity] = severity_summary.get(severity, 0) + 1
        (self.paths.nuclei / "severity-summary.json").write_text(
            json.dumps(severity_summary, indent=2),
            encoding="utf-8",
        )

    def write_ai_handoff(self) -> None:
        stage_name = "ai_handoff"
        outputs = [self.paths.root / "NEXT_STEPS_AI.md"]
        if self.should_skip(stage_name, outputs):
            return
        step("Write AI handoff prompts")
        self.state.mark_started(stage_name)
        content = f"""Use the prompts below with AI after this recon finishes.\n\nPrompt 1:\nAnalyze this js folder (JavaScript files) from a production web application.\n\nYour job is to perform a structured security-focused triage, not just a generic summary.\n\nPhase 1:\n\n1. Build an inventory of all JS files.\n2. Identify likely app code vs vendor/framework/minified library code.\n3. Extract and deduplicate:\n   - API endpoints\n   - GraphQL endpoints, queries, and mutations\n   - WebSocket endpoints\n   - Internal URLs, hostnames, IPs, S3/bucket references\n   - Tokens, keys, secrets, credentials, or suspicious constants\n4. Identify files containing likely security-relevant logic:\n   - auth\n   - role checks\n   - admin features\n   - payment\n   - booking\n   - applicant/profile handling\n   - upload/document/photo/facial verification flows\n5. Flag files with comments, debug code, feature flags, or disabled security checks.\n\nPhase 2:\nFor the most interesting files, explain:\n\n- why the file matters\n- what sensitive functionality it contains\n- what endpoints and parameters appear important\n- whether access control appears client-side only\n- whether IDs like userId, applicantId, appointmentId, slotId, paymentId, profileId are present\n- whether there are hidden or undocumented routes not obvious from the UI\n\nOutput files in {self.paths.js_output}:\n\n1. inventory.md\n2. interesting-files.txt\n3. endpoints.txt\n4. graphql.txt\n5. websocket.txt\n6. internal-assets.txt\n7. secrets-findings.md\n8. suspicious-client-side-controls.md\n9. final-summary.md\n\nBe concrete. Quote exact file paths and code snippets only when needed. Deduplicate aggressively. Prioritize findings that could help manual testing for IDOR, auth bypass, appointment logic abuse, reschedule tampering, payment tampering, and hidden admin functionality.\n\nPrompt 2:\nUsing the previous analysis, create a manual testing shortlist for Burp Suite.\nFor each high-value endpoint or JS-discovered function, provide:\n- endpoint/path\n- likely method\n- key parameters/IDs\n- why it is suspicious\n- specific manual tests to try for IDOR, auth bypass, workflow bypass, reschedule tampering, photo tampering, payment tampering, or hidden admin access\n\nWrite it to: {self.paths.burp_to / 'burp_manual_testing_shortlist.csv'}\n\nPrompt 3:\nCreate copy-paste Burp requests from burp-to/burp_manual_testing_shortlist.csv.\nStart with the highest-value hosts first from the JS analysis.\nWrite the requests into: {self.paths.burp_to}\n"""
        (self.paths.root / "NEXT_STEPS_AI.md").write_text(content, encoding="utf-8")
        self.state.mark_done(stage_name)

    def export_root_aliases(self) -> None:
        aliases = {
            self.paths.subs / "all_subdomains.txt": self.paths.root / "subdomains.txt",
            self.paths.alive / "alive_subdomains.txt": self.paths.root / "alive_subdomains.txt",
            self.paths.urls / "all_urls.txt": self.paths.root / "all_urls.txt",
            self.paths.urls / "filtered_urls.txt": self.paths.root / "filtered_urls.txt",
            self.paths.urls / "params.txt": self.paths.root / "params.txt",
            self.paths.alive / "alive_params.txt": self.paths.root / "alive_params.txt",
            self.paths.nuclei / "findings.json": self.paths.root / "findings.json",
            self.paths.nuclei / "findings.txt": self.paths.root / "findings.txt",
            self.paths.nuclei / "findings.csv": self.paths.root / "findings.csv",
        }
        for src, dst in aliases.items():
            if src.exists():
                dst.write_bytes(src.read_bytes())

    def write_summary(self) -> None:
        stage_name = "summary"
        step("Write summary")
        stats = {
            "subdomains": sum(1 for _ in read_lines(self.paths.subs / "all_subdomains.txt")),
            "alive_subdomains": sum(1 for _ in read_lines(self.paths.alive / "alive_subdomains.txt")),
            "all_urls": sum(1 for _ in read_lines(self.paths.urls / "all_urls.txt")),
            "filtered_urls": sum(1 for _ in read_lines(self.paths.urls / "filtered_urls.txt")),
            "params": sum(1 for _ in read_lines(self.paths.urls / "params.txt")),
            "alive_params": sum(1 for _ in read_lines(self.paths.alive / "alive_params.txt")),
            "js_urls": sum(1 for _ in read_lines(self.paths.js / "js-urls.txt")),
            "findings": sum(1 for _ in read_lines(self.paths.nuclei / "findings.jsonl")),
        }
        summary_path = self.paths.root / "SUMMARY.md"
        lines = [
            f"# {APP_NAME} Summary",
            "",
            f"- Target: `{self.target}`",
            f"- Output: `{self.paths.root}`",
            f"- Nuclei templates: `{self.templates_dir}`" if self.templates_dir else "- Nuclei templates: not found",
            "",
        ]
        for key, value in stats.items():
            lines.append(f"- {key.replace('_', ' ')}: {value}")
        summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        info(f"Done. Output folder: {self.paths.root}")
        self.state.mark_done(stage_name, **stats)


def main() -> int:
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    config = parse_args()
    try:
        targets = load_targets(config)
        tools = detect_tools(config)
    except Exception as exc:
        error(str(exc))
        return 1

    info(f"{APP_NAME} {APP_VERSION}")
    info(f"Targets loaded: {len(targets)}")
    for tool_name, tool in tools.items():
        if tool.path:
            info(f"tool[{tool_name}] = {tool.path}")
        elif tool.optional:
            warn(f"tool[{tool_name}] missing but optional")

    for index, target in enumerate(targets, start=1):
        if STOP_EVENT.is_set():
            break
        root = resolve_output_root(config, target, len(targets))
        runner = MFReconRunner(config, target, root, tools)
        try:
            step(f"[{index}/{len(targets)}] Recon for {target}")
            runner.run()
        except KeyboardInterrupt:
            warn("Interrupted by user")
            return 130
        except Exception as exc:
            runner.logger.log("error", "target_failed", target=target, error=str(exc))
            error(f"target {target} failed: {exc}")
            if len(targets) == 1:
                return 1
            continue
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
