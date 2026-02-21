#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              WebFuzz - Professional Web Fuzzing Tool             ║
║          For Legal Penetration Testing Labs (HTB/THM/CTF)        ║
║                github.com/aabderrafie/webfuzz                    ║
╚══════════════════════════════════════════════════════════════════╝

Author  : abderrafie (github.com/aabderrafie)
Version : 2.0.0
License : MIT
Purpose : Automated web fuzzing for authorized security testing ONLY
"""

# ─── Standard Library ────────────────────────────────────────────────────────
import os
import sys
import json
import time
import shutil
import signal
import argparse
import threading
import subprocess
import urllib.parse
import urllib.request
import urllib.error
import http.client
import socket
import re
import glob
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict, Tuple, Any

# ─── Constants ───────────────────────────────────────────────────────────────

VERSION = "2.0.0"
BANNER = r"""
\033[1;31m
 ██╗    ██╗███████╗██████╗ ███████╗██╗   ██╗███████╗███████╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██║   ██║╚════██║╚════██║
 ██║ █╗ ██║█████╗  ██████╔╝█████╗  ██║   ██║    ██╔╝    ██╔╝
 ██║███╗██║██╔══╝  ██╔══██╗██╔══╝  ██║   ██║   ██╔╝    ██╔╝
 ╚███╔███╔╝███████╗██████╔╝██║     ╚██████╔╝   ██║     ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝      ╚═════╝    ╚═╝     ╚═╝
\033[0m\033[1;33m  Professional Web Fuzzing Tool v{version} — Legal PTLabs Only\033[0m
\033[0;90m  HTB | TryHackMe | CTF | Authorized Engagements\033[0m
""".format(version=VERSION)

# HTTP status codes to match (interesting responses)
DEFAULT_MATCH_CODES = {200, 201, 204, 301, 302, 307, 401, 403, 405}

# File extensions for file fuzzing
DEFAULT_EXTENSIONS = [
    ".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".js",
    ".css", ".json", ".xml", ".txt", ".bak", ".old", ".log",
    ".sql", ".zip", ".tar", ".gz", ".rar", ".env", ".config",
    ".conf", ".yaml", ".yml", ".toml", ".ini", ".sh", ".py"
]

# Keyword weights for wordlist scoring
WORDLIST_KEYWORDS = {
    "directory": 10, "dir": 8, "common": 9, "medium": 7, "large": 5,
    "small": 8, "big": 4, "web": 9, "http": 8, "subdomain": 10,
    "vhost": 10, "param": 9, "parameter": 9, "api": 8, "raft": 9,
    "content": 7, "discovery": 9, "fuzz": 9, "words": 6,
    "combined": 5, "dirbuster": 9, "dirb": 9, "feroxbuster": 9,
    "2.3": 7, "million": 3, "top": 8
}

# Common SecLists / Kali wordlist paths
WORDLIST_SEARCH_PATHS = [
    "/usr/share/seclists",
    "/usr/share/wordlists",
    "/usr/share/dirb/wordlists",
    "/usr/share/dirbuster/wordlists",
    "/opt/SecLists",
    "/opt/wordlists",
    os.path.expanduser("~/wordlists"),
    os.path.expanduser("~/SecLists"),
]

# ─── ANSI Color Helpers ───────────────────────────────────────────────────────

class C:
    """Terminal color codes."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[1;31m"
    GREEN   = "\033[1;32m"
    YELLOW  = "\033[1;33m"
    BLUE    = "\033[1;34m"
    CYAN    = "\033[1;36m"
    MAGENTA = "\033[1;35m"
    GREY    = "\033[0;90m"
    WHITE   = "\033[1;37m"
    DIM     = "\033[2m"

def print_banner():
    print(BANNER)

def info(msg: str):    print(f"{C.BLUE}[*]{C.RESET} {msg}")
def success(msg: str): print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg: str):    print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def error(msg: str):   print(f"{C.RED}[-]{C.RESET} {msg}")
def debug(msg: str):   print(f"{C.GREY}[D]{C.RESET} {msg}")
def found(msg: str):   print(f"{C.MAGENTA}[FOUND]{C.RESET} {msg}")
def suggest(msg: str): print(f"{C.CYAN}[SUGGEST]{C.RESET} {msg}")
def section(title: str):
    width = 60
    print(f"\n{C.BOLD}{C.CYAN}{'─'*width}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'─'*width}{C.RESET}")

# ─── Signal Handler ───────────────────────────────────────────────────────────

_STOP_EVENT = threading.Event()

def _signal_handler(sig, frame):
    warn("Ctrl+C detected — gracefully stopping all threads...")
    _STOP_EVENT.set()
    sys.exit(0)

signal.signal(signal.SIGINT, _signal_handler)

# ─── Tool Checker ─────────────────────────────────────────────────────────────

class ToolChecker:
    """Verify external tool availability."""

    TOOLS = {
        "ffuf":      "Fast web fuzzer (core tool)",
        "gobuster":  "Directory/DNS bruter",
        "wenum":     "Web enumeration tool (optional)",
        "curl":      "HTTP client utility",
    }

    @staticmethod
    def check_all() -> Dict[str, bool]:
        results = {}
        for tool in ToolChecker.TOOLS:
            path = shutil.which(tool)
            results[tool] = path is not None
        return results

    @staticmethod
    def print_status():
        section("Tool Availability Check")
        available = ToolChecker.check_all()
        for tool, desc in ToolChecker.TOOLS.items():
            status = available.get(tool, False)
            mark = f"{C.GREEN}✔ INSTALLED{C.RESET}" if status else f"{C.RED}✘ MISSING  {C.RESET}"
            optional = "(optional)" if tool == "wenum" else ""
            print(f"  {mark}  {C.BOLD}{tool:<12}{C.RESET} — {desc} {C.GREY}{optional}{C.RESET}")

        missing_core = [t for t in ["ffuf", "gobuster"] if not available.get(t)]
        if missing_core:
            print()
            warn(f"Missing core tools: {', '.join(missing_core)}")
            info("Install with: sudo apt install ffuf gobuster")
        return available

# ─── Wordlist Engine ──────────────────────────────────────────────────────────

class WordlistEngine:
    """
    Dynamically discovers, scores, and selects the best available
    wordlists for each fuzzing category.
    """

    CATEGORY_HINTS = {
        "directory":  ["directory", "dir", "web", "common", "raft", "dirbuster", "dirb", "content", "discovery"],
        "file":       ["files", "file", "extension", "web", "content", "common"],
        "subdomain":  ["subdomain", "sub", "dns", "host", "resolvers"],
        "vhost":      ["vhost", "virtual", "subdomain", "host"],
        "parameter":  ["param", "parameter", "query", "get", "post", "burp", "api"],
        "header":     ["header", "ua", "user-agent", "x-forwarded"],
        "json":       ["json", "api", "body", "payload"],
        "password":   ["password", "pass", "rockyou", "common"],
    }

    def __init__(self):
        self._cache: Dict[str, List[Dict]] = {}

    def _find_all_wordlists(self) -> List[Path]:
        """Recursively discover all .txt wordlist files."""
        found = []
        for base in WORDLIST_SEARCH_PATHS:
            bp = Path(base)
            if bp.is_dir():
                for p in bp.rglob("*.txt"):
                    try:
                        if p.stat().st_size > 0:
                            found.append(p)
                    except OSError:
                        continue
        return found

    def _score_wordlist(self, path: Path, category: str) -> float:
        """
        Score a wordlist path based on:
        - Filename keyword relevance (category + generic)
        - File size (moderate size preferred for 'fast', large for 'deep')
        - Word count estimate
        """
        name = path.stem.lower()
        full = str(path).lower()
        score = 0.0

        # Category-specific keyword bonus
        hints = self.CATEGORY_HINTS.get(category, [])
        for hint in hints:
            if hint in name:
                score += 20
            elif hint in full:
                score += 8

        # Generic keyword scoring
        for kw, weight in WORDLIST_KEYWORDS.items():
            if kw in name:
                score += weight

        # Penalize very broad/huge wordlists for fast scoring
        try:
            size_mb = path.stat().st_size / (1024 * 1024)
        except OSError:
            return 0.0

        # Sweet spot: 50KB – 5MB gets a bonus
        if 0.05 <= size_mb <= 5:
            score += 15
        elif size_mb > 50:
            score -= 20  # massive list — not for fast mode
        elif size_mb < 0.01:
            score -= 5   # too tiny

        # Penalize deep subdirectory paths (usually specialty lists)
        depth = len(path.parts)
        score -= max(0, depth - 6) * 0.5

        return score

    def get_wordlists_for_category(self, category: str, fast: bool = True) -> List[Path]:
        """
        Return ranked wordlist paths for the given category.
        fast=True  → prefers smaller, highly relevant lists
        fast=False → allows larger lists
        """
        cache_key = f"{category}_{fast}"
        if cache_key in self._cache:
            return [Path(p) for p in self._cache[cache_key]]

        all_lists = self._find_all_wordlists()
        if not all_lists:
            return []

        scored = []
        for wl in all_lists:
            s = self._score_wordlist(wl, category)
            if fast:
                try:
                    size_mb = wl.stat().st_size / (1024 * 1024)
                    if size_mb > 10:
                        continue  # skip huge lists in fast mode
                except OSError:
                    continue
            scored.append((s, wl))

        scored.sort(key=lambda x: x[0], reverse=True)
        ranked = [wl for _, wl in scored if _ > 0]

        self._cache[cache_key] = [str(p) for p in ranked]
        return ranked

    def best(self, category: str, fast: bool = True) -> Optional[Path]:
        """Return single best wordlist for category."""
        results = self.get_wordlists_for_category(category, fast)
        return results[0] if results else None

    def escalate(self, category: str, exclude: List[Path]) -> Optional[Path]:
        """
        Return next-best wordlist, excluding already-used ones.
        Used when initial scan yields no results.
        """
        ex_set = {str(p) for p in exclude}
        candidates = self.get_wordlists_for_category(category, fast=False)
        for wl in candidates:
            if str(wl) not in ex_set:
                return wl
        return None

    def print_selected(self, category: str, path: Optional[Path], fast: bool):
        mode = "FAST" if fast else "DEEP"
        if path:
            try:
                lines = sum(1 for _ in open(path, "rb"))
            except Exception:
                lines = 0
            size_kb = path.stat().st_size // 1024
            info(f"Wordlist [{mode}] for '{category}': {C.CYAN}{path}{C.RESET} "
                 f"({C.YELLOW}{lines:,} words{C.RESET}, {size_kb}KB)")
        else:
            warn(f"No wordlist found for category '{category}'. "
                 "Install SecLists: sudo apt install seclists")

# ─── Output Manager ───────────────────────────────────────────────────────────

class OutputManager:
    """Creates structured output directories and manages result files."""

    SUBDIRS = [
        "directories", "files", "parameters", "methods",
        "subdomains", "vhosts", "headers", "json", "logs"
    ]

    def __init__(self, target: str, base_dir: str = "results"):
        # Sanitize target name for filesystem use
        safe = re.sub(r"[^\w\-.]", "_", target.replace("://", "_").strip("/"))
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.root = Path(base_dir) / f"{safe}_{ts}"
        self._paths: Dict[str, Path] = {}
        self._create_structure()
        self._setup_logging()

    def _create_structure(self):
        for sub in self.SUBDIRS:
            p = self.root / sub
            p.mkdir(parents=True, exist_ok=True)
            self._paths[sub] = p
        info(f"Output directory: {C.CYAN}{self.root}{C.RESET}")

    def _setup_logging(self):
        log_file = self._paths["logs"] / "scan.log"
        logging.basicConfig(
            filename=str(log_file),
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        logging.info("WebFuzz session started")

    def path(self, category: str) -> Path:
        return self._paths.get(category, self.root)

    def save_result(self, category: str, name: str, data: str, metadata: dict = None):
        """Save raw result with optional metadata header."""
        out_dir = self.path(category)
        ts = datetime.now().strftime("%H%M%S")
        fname = f"{name}_{ts}.txt"
        fpath = out_dir / fname

        header = []
        if metadata:
            header.append("=" * 60)
            header.append("SCAN METADATA")
            header.append("=" * 60)
            for k, v in metadata.items():
                header.append(f"{k}: {v}")
            header.append("=" * 60)
            header.append("")

        with open(fpath, "w") as f:
            if header:
                f.write("\n".join(header) + "\n")
            f.write(data)

        success(f"Results saved → {C.CYAN}{fpath}{C.RESET}")
        logging.info(f"Saved {category}/{fname} ({len(data)} bytes)")
        return fpath

    def save_json(self, category: str, name: str, data: dict):
        out_dir = self.path(category)
        ts = datetime.now().strftime("%H%M%S")
        fname = f"{name}_{ts}.json"
        fpath = out_dir / fname
        with open(fpath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return fpath

# ─── HTTP Engine ──────────────────────────────────────────────────────────────

class HTTPEngine:
    """
    Pure-stdlib HTTP engine for baseline detection,
    smart matching, and intelligent behavior hints.
    """

    def __init__(self, target: str, timeout: int = 10,
                 match_codes: set = None, threads: int = 50,
                 headers: dict = None, cookies: str = None):
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.match_codes = match_codes or DEFAULT_MATCH_CODES
        self.threads = threads
        self.custom_headers = headers or {}
        self.cookies = cookies
        self.baseline_size: Optional[int] = None
        self.proto = "https" if "https://" in target else "http"
        self.results: List[Dict] = []
        self._lock = threading.Lock()

    # ── Baseline Detection ──────────────────────────────────────────────

    def detect_baseline(self) -> dict:
        """
        Send a random path request to establish 404 baseline.
        Returns baseline info dict.
        """
        rand_path = f"/webfuzz_nonexistent_{hashlib.md5(b'baseline').hexdigest()[:8]}"
        try:
            code, size, headers, body = self._request("GET", rand_path)
            self.baseline_size = size
            return {
                "status":      code,
                "size":        size,
                "server":      headers.get("server", "unknown"),
                "content_type": headers.get("content-type", "unknown"),
            }
        except Exception as e:
            warn(f"Baseline detection failed: {e}")
            return {}

    def detect_protocol(self) -> str:
        """Auto-detect http vs https."""
        for proto in ("https", "http"):
            try:
                url = f"{proto}://{self.target.split('://')[-1]}"
                req = urllib.request.Request(url + "/", method="HEAD")
                req.add_unverifiable_header("User-Agent", "WebFuzz/2.0")
                urllib.request.urlopen(req, timeout=5)
                return proto
            except Exception:
                continue
        return "http"

    # ── Core Request ────────────────────────────────────────────────────

    def _request(self, method: str, path: str,
                 body: str = None, extra_headers: dict = None
                 ) -> Tuple[int, int, dict, bytes]:
        """
        Low-level request. Returns (status_code, body_size, headers, body_bytes).
        """
        url = self.target + path
        data = body.encode() if body else None

        req = urllib.request.Request(url, data=data, method=method)
        req.add_unverifiable_header("User-Agent", "Mozilla/5.0 (WebFuzz/2.0)")
        req.add_unverifiable_header("Accept", "*/*")

        if self.cookies:
            req.add_unverifiable_header("Cookie", self.cookies)
        for k, v in self.custom_headers.items():
            req.add_unverifiable_header(k, v)
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_unverifiable_header(k, v)

        try:
            # Disable redirect following to detect redirects
            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler()
            )
            resp = opener.open(req, timeout=self.timeout)
            raw = resp.read(65536)
            hdrs = dict(resp.headers)
            return resp.status, len(raw), {k.lower(): v for k, v in hdrs.items()}, raw
        except urllib.error.HTTPError as e:
            raw = e.read(1024) if hasattr(e, "read") else b""
            return e.code, len(raw), {}, raw
        except (urllib.error.URLError, socket.timeout, ConnectionResetError):
            return 0, 0, {}, b""

    # ── Smart Matching ──────────────────────────────────────────────────

    def _is_interesting(self, code: int, size: int) -> bool:
        if code not in self.match_codes:
            return False
        # Filter uniform 404 content length
        if self.baseline_size and abs(size - self.baseline_size) < 20 and code not in {200, 201}:
            return False
        return True

    # ── Fuzz Worker ─────────────────────────────────────────────────────

    def fuzz_paths(self, paths: List[str], method: str = "GET",
                   prefix: str = "", suffix: str = "",
                   body_template: str = None,
                   extra_headers: dict = None) -> List[Dict]:
        """
        Fuzz a list of paths using thread pool.
        Returns list of interesting result dicts.
        """
        results = []
        total = len(paths)
        done = [0]
        lock = threading.Lock()

        def worker(word: str):
            if _STOP_EVENT.is_set():
                return
            path = f"/{prefix}{word}{suffix}"
            body = body_template.replace("FUZZ", word) if body_template else None
            code, size, hdrs, raw = self._request(method, path, body, extra_headers)

            with lock:
                done[0] += 1
                if done[0] % 100 == 0 or done[0] == total:
                    pct = done[0] * 100 // total
                    bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                    print(f"\r  {C.CYAN}[{bar}]{C.RESET} {done[0]}/{total} "
                          f"({pct}%)  ", end="", flush=True)

            if self._is_interesting(code, size):
                r = {
                    "path":    path,
                    "word":    word,
                    "method":  method,
                    "code":    code,
                    "size":    size,
                    "headers": hdrs,
                    "time":    datetime.now().isoformat(),
                }
                with lock:
                    results.append(r)
                    color = C.GREEN if code == 200 else C.YELLOW if code in {301,302,307} else C.RED
                    print(f"\r{color}[{code}]{C.RESET} {path:<55} {C.GREY}{size} bytes{C.RESET}")
                    # Smart suggestions
                    if code == 403:
                        suggest(f"403 at {path} — try bypass: X-Original-URL, X-Rewrite-URL headers")
                    if "upload" in path.lower() or "file" in path.lower():
                        suggest(f"Upload endpoint at {path} — consider PUT fuzzing")
                    if code == 200 and hdrs.get("content-type", "").startswith("application/json"):
                        suggest(f"API response at {path} — try JSON body fuzzing")
                    if code == 200 and ("login" in path.lower() or "auth" in path.lower()):
                        suggest(f"Login endpoint at {path} — try POST parameter fuzzing")
            return None

        print()
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(worker, p) for p in paths]
            for f in as_completed(futures):
                if _STOP_EVENT.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                f.result()
        print()
        return results

# ─── Wordlist Reader ─────────────────────────────────────────────────────────

def load_wordlist(path: Path) -> List[str]:
    """Load wordlist, stripping comments and blank lines."""
    words = []
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    words.append(line)
    except OSError as e:
        error(f"Cannot read wordlist {path}: {e}")
    return words

# ─── ffuf / gobuster Wrapper ──────────────────────────────────────────────────

class ExternalFuzzer:
    """
    Wraps ffuf and gobuster calls, streaming output live
    and saving results to file.
    """

    def __init__(self, output_manager: OutputManager, threads: int = 50,
                 timeout: int = 10, match_codes: str = "200,201,204,301,302,307,401,403"):
        self.om = output_manager
        self.threads = threads
        self.timeout = timeout
        self.match_codes = match_codes

    def _run(self, cmd: List[str], category: str, label: str,
             metadata: dict = None) -> Tuple[int, str]:
        """Execute subprocess, stream stdout, capture output."""
        info(f"Running: {C.GREY}{' '.join(cmd)}{C.RESET}")
        output_lines = []
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
            for line in proc.stdout:
                stripped = line.rstrip()
                if stripped:
                    print(f"  {C.DIM}{stripped}{C.RESET}")
                    output_lines.append(stripped)
                if _STOP_EVENT.is_set():
                    proc.terminate()
                    break
            proc.wait()
            rc = proc.returncode
        except FileNotFoundError:
            error(f"Tool not found: {cmd[0]}")
            return -1, ""
        except Exception as e:
            error(f"Subprocess error: {e}")
            return -1, ""

        raw = "\n".join(output_lines)
        if raw.strip():
            self.om.save_result(category, label, raw, metadata)
        return rc, raw

    # ── ffuf wrappers ─────────────────────────────────────────────────

    def ffuf_dir(self, target: str, wordlist: Path, extensions: str = "") -> int:
        """Directory + file fuzzing via ffuf."""
        cmd = [
            "ffuf", "-u", f"{target}/FUZZ",
            "-w", str(wordlist),
            "-t", str(self.threads),
            "-timeout", str(self.timeout),
            "-mc", self.match_codes,
            "-c", "-v",
        ]
        if extensions:
            cmd += ["-e", extensions]
        meta = {"tool": "ffuf", "mode": "directory",
                "target": target, "wordlist": str(wordlist),
                "threads": self.threads}
        rc, _ = self._run(cmd, "directories", "ffuf_dir", meta)
        return rc

    def ffuf_params(self, target: str, wordlist: Path, method: str = "GET") -> int:
        """GET/POST parameter fuzzing via ffuf."""
        if method.upper() == "GET":
            url = f"{target}?FUZZ=value"
        else:
            url = target
        cmd = [
            "ffuf", "-u", url,
            "-w", str(wordlist),
            "-t", str(self.threads),
            "-timeout", str(self.timeout),
            "-mc", self.match_codes,
            "-c", "-v",
        ]
        if method.upper() == "POST":
            cmd += ["-X", "POST", "-d", "FUZZ=value",
                    "-H", "Content-Type: application/x-www-form-urlencoded"]
        meta = {"tool": "ffuf", "mode": f"param_{method}",
                "target": target, "wordlist": str(wordlist)}
        rc, _ = self._run(cmd, "parameters", f"ffuf_param_{method.lower()}", meta)
        return rc

    def ffuf_vhost(self, target: str, wordlist: Path, domain: str) -> int:
        """VHost fuzzing via ffuf."""
        # Extract base URL without port for Host header
        parsed = urllib.parse.urlparse(target)
        cmd = [
            "ffuf", "-u", target,
            "-w", str(wordlist),
            "-H", f"Host: FUZZ.{domain}",
            "-t", str(self.threads),
            "-timeout", str(self.timeout),
            "-mc", self.match_codes,
            "-c", "-v",
        ]
        meta = {"tool": "ffuf", "mode": "vhost", "domain": domain,
                "target": target, "wordlist": str(wordlist)}
        rc, _ = self._run(cmd, "vhosts", "ffuf_vhost", meta)
        return rc

    def ffuf_json(self, target: str, wordlist: Path, json_template: str) -> int:
        """JSON body fuzzing via ffuf."""
        cmd = [
            "ffuf", "-u", target,
            "-w", str(wordlist),
            "-X", "POST",
            "-d", json_template,
            "-H", "Content-Type: application/json",
            "-t", str(self.threads),
            "-timeout", str(self.timeout),
            "-mc", self.match_codes,
            "-c", "-v",
        ]
        meta = {"tool": "ffuf", "mode": "json_body",
                "target": target, "template": json_template}
        rc, _ = self._run(cmd, "json", "ffuf_json", meta)
        return rc

    def ffuf_recursive(self, target: str, wordlist: Path,
                       depth: int = 2, extensions: str = "") -> int:
        """Recursive directory fuzzing via ffuf."""
        out_file = str(self.om.path("directories") / "ffuf_recursive.json")
        cmd = [
            "ffuf", "-u", f"{target}/FUZZ",
            "-w", str(wordlist),
            "-t", str(self.threads),
            "-timeout", str(self.timeout),
            "-mc", self.match_codes,
            "-recursion", "-recursion-depth", str(depth),
            "-c", "-v",
            "-o", out_file, "-of", "json",
        ]
        if extensions:
            cmd += ["-e", extensions]
        meta = {"tool": "ffuf", "mode": "recursive",
                "depth": depth, "target": target, "wordlist": str(wordlist)}
        rc, _ = self._run(cmd, "directories", "ffuf_recursive", meta)
        return rc

    def gobuster_dns(self, domain: str, wordlist: Path) -> int:
        """Subdomain enumeration via gobuster dns."""
        cmd = [
            "gobuster", "dns",
            "-d", domain,
            "-w", str(wordlist),
            "-t", str(self.threads),
            "--timeout", f"{self.timeout}s",
        ]
        meta = {"tool": "gobuster", "mode": "dns",
                "domain": domain, "wordlist": str(wordlist)}
        rc, _ = self._run(cmd, "subdomains", "gobuster_dns", meta)
        return rc

    def gobuster_dir(self, target: str, wordlist: Path, extensions: str = "") -> int:
        """Directory bruting via gobuster dir."""
        cmd = [
            "gobuster", "dir",
            "-u", target,
            "-w", str(wordlist),
            "-t", str(self.threads),
            "--timeout", f"{self.timeout}s",
            "-s", self.match_codes,
        ]
        if extensions:
            cmd += ["-x", extensions.lstrip(".")]
        meta = {"tool": "gobuster", "mode": "dir",
                "target": target, "wordlist": str(wordlist)}
        rc, _ = self._run(cmd, "directories", "gobuster_dir", meta)
        return rc

# ─── HTTP Method Tester ────────────────────────────────────────────────────────

class MethodTester:
    """
    Tests HTTP methods (OPTIONS, PUT, DELETE, PATCH, HEAD)
    against discovered paths.
    """

    ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

    def __init__(self, engine: HTTPEngine, output_manager: OutputManager):
        self.eng = engine
        self.om = output_manager

    def test_options(self, paths: List[str]) -> Dict[str, str]:
        """Discover allowed methods via OPTIONS."""
        section("OPTIONS Discovery")
        results = {}
        for path in paths:
            code, size, hdrs, _ = self.eng._request("OPTIONS", path)
            allow = hdrs.get("allow", "")
            if allow:
                found(f"OPTIONS {path} → Allow: {C.GREEN}{allow}{C.RESET}")
                results[path] = allow
                if "PUT" in allow:
                    suggest(f"PUT allowed at {path} — try file upload")
                if "DELETE" in allow:
                    suggest(f"DELETE allowed at {path} — test resource deletion")
        return results

    def test_method(self, path: str, method: str,
                    body: str = None) -> Dict:
        """Test a specific HTTP method against a path."""
        code, size, hdrs, raw = self.eng._request(method, path, body)
        return {"method": method, "path": path,
                "code": code, "size": size, "headers": hdrs}

    def test_all_methods(self, paths: List[str]) -> List[Dict]:
        """Test all HTTP methods against a list of paths."""
        section("HTTP Method Testing")
        all_results = []
        for path in paths:
            for method in self.ALL_METHODS:
                if _STOP_EVENT.is_set():
                    return all_results
                r = self.test_method(path, method)
                if r["code"] in DEFAULT_MATCH_CODES:
                    color = C.GREEN if r["code"] == 200 else C.YELLOW
                    found(f"{color}{method:<8}{C.RESET} {path} → {r['code']} ({r['size']} bytes)")
                    all_results.append(r)

        if all_results:
            raw = json.dumps(all_results, indent=2)
            self.om.save_result("methods", "method_test", raw)
        return all_results

    def test_put_upload(self, path: str, content: str = "webfuzz_test") -> Dict:
        """Attempt PUT file upload to test path."""
        section(f"PUT Upload Test: {path}")
        r = self.test_method(path, "PUT", content)
        color = C.GREEN if r["code"] in {200, 201, 204} else C.RED
        info(f"PUT {path} → {color}{r['code']}{C.RESET}")
        if r["code"] in {200, 201, 204}:
            warn("PUT upload succeeded! Verify file was written.")
        return r

    def test_header_injection(self, path: str,
                              wordlist: Path) -> List[Dict]:
        """Fuzz custom headers for interesting responses."""
        section(f"Header Fuzzing: {path}")
        words = load_wordlist(wordlist)
        results = []
        test_headers = [
            "X-Forwarded-For", "X-Original-URL", "X-Rewrite-URL",
            "X-Custom-IP-Authorization", "X-Host", "Forwarded",
        ]
        for hdr in test_headers:
            for word in words[:100]:  # limit header fuzz
                if _STOP_EVENT.is_set():
                    return results
                code, size, hdrs, _ = self.eng._request(
                    "GET", path, extra_headers={hdr: word})
                if code in DEFAULT_MATCH_CODES and code != 404:
                    r = {"header": hdr, "value": word,
                         "code": code, "size": size}
                    results.append(r)
                    found(f"Header {C.CYAN}{hdr}: {word}{C.RESET} → {code}")

        if results:
            self.om.save_result("headers", "header_fuzz",
                                json.dumps(results, indent=2))
        return results

# ─── Cookie Fuzzer ────────────────────────────────────────────────────────────

class CookieFuzzer:
    """Fuzz cookie values for IDOR, auth bypass, etc."""

    def __init__(self, engine: HTTPEngine, output_manager: OutputManager):
        self.eng = engine
        self.om = output_manager

    def fuzz(self, path: str, cookie_name: str,
             wordlist: Path, method: str = "GET") -> List[Dict]:
        section(f"Cookie Fuzzing: {cookie_name}")
        words = load_wordlist(wordlist)
        results = []

        def worker(word: str):
            orig_cookies = self.eng.cookies
            self.eng.cookies = f"{cookie_name}={word}"
            code, size, hdrs, _ = self.eng._request(method, path)
            self.eng.cookies = orig_cookies
            if code in DEFAULT_MATCH_CODES:
                r = {"cookie": f"{cookie_name}={word}",
                     "code": code, "size": size}
                results.append(r)
                found(f"Cookie {C.CYAN}{cookie_name}={word}{C.RESET} → {code}")

        with ThreadPoolExecutor(max_workers=self.eng.threads) as ex:
            list(ex.map(worker, words))

        if results:
            self.om.save_result("headers", "cookie_fuzz",
                                json.dumps(results, indent=2))
        return results

# ─── Main Scanner ─────────────────────────────────────────────────────────────

class WebFuzz:
    """
    Orchestrates all fuzzing modules. Entry point for CLI and menu modes.
    """

    def __init__(self, config: dict):
        self.target     = config["target"].rstrip("/")
        self.threads    = config.get("threads", 50)
        self.timeout    = config.get("timeout", 10)
        self.deep       = config.get("deep", False)
        self.extensions = config.get("extensions", DEFAULT_EXTENSIONS)
        self.domain     = config.get("domain", "")
        self.cookies    = config.get("cookies", "")
        self.add_headers = config.get("headers", {})

        # Auto-detect protocol
        if not self.target.startswith("http"):
            info("Auto-detecting protocol...")
            dummy_eng = HTTPEngine(f"http://{self.target}", self.timeout)
            proto = dummy_eng.detect_protocol()
            self.target = f"{proto}://{self.target}"
            success(f"Protocol detected: {proto.upper()}")

        self.wl_engine   = WordlistEngine()
        self.om          = OutputManager(self.target)
        self.http        = HTTPEngine(
            self.target, self.timeout,
            threads=self.threads,
            cookies=self.cookies,
            headers=self.add_headers,
        )
        self.ext_fuzzer  = ExternalFuzzer(self.om, self.threads, self.timeout)
        self.method_tester = MethodTester(self.http, self.om)
        self.cookie_fuzzer = CookieFuzzer(self.http, self.om)

        self._used_wordlists: Dict[str, List[Path]] = {}

    def _get_wordlist(self, category: str) -> Optional[Path]:
        """Get best wordlist, tracking used for escalation."""
        used = self._used_wordlists.get(category, [])
        if not used:
            wl = self.wl_engine.best(category, fast=not self.deep)
        else:
            wl = self.wl_engine.escalate(category, used)

        if wl:
            self._used_wordlists.setdefault(category, []).append(wl)
            self.wl_engine.print_selected(category, wl, not self.deep)
        else:
            warn(f"No wordlist for '{category}'. Install SecLists: sudo apt install seclists")
        return wl

    def _escalate_if_empty(self, results: list, category: str,
                            callback) -> list:
        """If results empty, escalate to bigger wordlist and re-run."""
        if results:
            return results
        warn(f"No results for '{category}' — escalating to larger wordlist...")
        wl = self._get_wordlist(category)
        if not wl:
            return []
        return callback(wl)

    # ── Scan Modules ─────────────────────────────────────────────────────

    def run_baseline(self):
        section("Baseline Detection")
        bl = self.http.detect_baseline()
        if bl:
            info(f"Server      : {C.CYAN}{bl.get('server')}{C.RESET}")
            info(f"404 size    : {C.CYAN}{bl.get('size')} bytes{C.RESET}")
            info(f"Content-Type: {C.CYAN}{bl.get('content_type')}{C.RESET}")
        return bl

    def run_directory_fuzz(self):
        section("Directory Fuzzing")
        wl = self._get_wordlist("directory")
        if not wl:
            return []

        tools = ToolChecker.check_all()
        if tools.get("ffuf"):
            ext_str = ",".join(self.extensions)
            rc = self.ext_fuzzer.ffuf_dir(self.target, wl, ext_str)
            return [{"tool": "ffuf", "rc": rc}]
        elif tools.get("gobuster"):
            ext_str = ",".join(e.lstrip(".") for e in self.extensions)
            rc = self.ext_fuzzer.gobuster_dir(self.target, wl, ext_str)
            return [{"tool": "gobuster", "rc": rc}]
        else:
            warn("Neither ffuf nor gobuster found. Using built-in engine.")
            words = load_wordlist(wl)
            results = self.http.fuzz_paths(words, "GET")
            results = self._escalate_if_empty(
                results, "directory",
                lambda w: self.http.fuzz_paths(load_wordlist(w), "GET")
            )
            if results:
                self.om.save_result("directories", "dir_fuzz",
                                    json.dumps(results, indent=2))
            return results

    def run_file_fuzz(self):
        section("File / Extension Fuzzing")
        wl = self._get_wordlist("file")
        if not wl:
            return []

        tools = ToolChecker.check_all()
        ext_str = ",".join(self.extensions)
        if tools.get("ffuf"):
            self.ext_fuzzer.ffuf_dir(self.target, wl, ext_str)
        else:
            words = load_wordlist(wl)
            all_words = []
            for word in words:
                all_words.append(word)
                for ext in self.extensions:
                    all_words.append(f"{word}{ext}")
            results = self.http.fuzz_paths(all_words, "GET")
            if results:
                self.om.save_result("files", "file_fuzz",
                                    json.dumps(results, indent=2))

    def run_recursive_fuzz(self, depth: int = 2):
        section(f"Recursive Fuzzing (depth={depth})")
        wl = self._get_wordlist("directory")
        if not wl:
            return

        tools = ToolChecker.check_all()
        ext_str = ",".join(self.extensions)
        if tools.get("ffuf"):
            self.ext_fuzzer.ffuf_recursive(self.target, wl, depth, ext_str)
        else:
            warn("ffuf required for recursive fuzzing. Install it: sudo apt install ffuf")

    def run_param_fuzz(self, method: str = "GET"):
        section(f"Parameter Fuzzing ({method})")
        wl = self._get_wordlist("parameter")
        if not wl:
            return

        tools = ToolChecker.check_all()
        if tools.get("ffuf"):
            self.ext_fuzzer.ffuf_params(self.target, wl, method)
        else:
            words = load_wordlist(wl)
            if method.upper() == "GET":
                results = self.http.fuzz_paths(
                    words, "GET", suffix="",
                    extra_headers=None
                )
            else:
                results = self.http.fuzz_paths(
                    words, method,
                    body_template=f"FUZZ=test&submit=1"
                )
            if results:
                self.om.save_result("parameters", f"param_{method.lower()}",
                                    json.dumps(results, indent=2))

    def run_method_fuzz(self, paths: List[str] = None):
        section("HTTP Method Testing")
        if not paths:
            paths = ["/", "/api", "/admin", "/upload"]
        self.method_tester.test_options(paths)
        self.method_tester.test_all_methods(paths)

    def run_put_fuzz(self, path: str = "/upload/test.txt"):
        section("PUT Method Fuzzing")
        self.method_tester.test_put_upload(path)

    def run_subdomain_fuzz(self, domain: str = None):
        section("Subdomain Fuzzing")
        domain = domain or self.domain
        if not domain:
            # Try to extract domain from target
            parsed = urllib.parse.urlparse(self.target)
            domain = parsed.hostname or ""
        if not domain:
            error("Domain required for subdomain fuzzing. Use --domain flag.")
            return

        wl = self._get_wordlist("subdomain")
        if not wl:
            return

        tools = ToolChecker.check_all()
        if tools.get("gobuster"):
            self.ext_fuzzer.gobuster_dns(domain, wl)
        elif tools.get("ffuf"):
            # ffuf-based subdomain via Host header
            base = domain.split("://")[-1].split("/")[0]
            cmd = [
                "ffuf", "-u", self.target,
                "-w", str(wl),
                "-H", f"Host: FUZZ.{base}",
                "-t", str(self.threads),
                "-mc", "200,301,302,307,401,403",
                "-c", "-v",
            ]
            info(f"Running: {C.GREY}{' '.join(cmd)}{C.RESET}")
            subprocess.run(cmd)
        else:
            warn("gobuster or ffuf required for subdomain fuzzing.")

    def run_vhost_fuzz(self, domain: str = None):
        section("VHost Fuzzing")
        domain = domain or self.domain
        if not domain:
            parsed = urllib.parse.urlparse(self.target)
            domain = parsed.hostname or ""
        if not domain:
            error("Domain required for VHost fuzzing. Use --domain flag.")
            return

        wl = self._get_wordlist("vhost")
        if not wl:
            return

        tools = ToolChecker.check_all()
        if tools.get("ffuf"):
            self.ext_fuzzer.ffuf_vhost(self.target, wl, domain)
        else:
            warn("ffuf required for VHost fuzzing.")

    def run_header_fuzz(self, path: str = "/"):
        section("Header Fuzzing")
        wl = self._get_wordlist("parameter")
        if not wl:
            return
        self.method_tester.test_header_injection(path, wl)

    def run_cookie_fuzz(self, cookie_name: str = "session",
                        path: str = "/"):
        section("Cookie Fuzzing")
        wl = self._get_wordlist("password")
        if not wl:
            return
        self.cookie_fuzzer.fuzz(path, cookie_name, wl)

    def run_json_fuzz(self, path: str = "/api",
                      template: str = '{"key": "FUZZ"}'):
        section("JSON Body Fuzzing")
        wl = self._get_wordlist("json")
        if not wl:
            wl = self._get_wordlist("parameter")
        if not wl:
            return

        tools = ToolChecker.check_all()
        target_url = self.target + path
        if tools.get("ffuf"):
            self.ext_fuzzer.ffuf_json(target_url, wl, template)
        else:
            words = load_wordlist(wl)
            results = self.http.fuzz_paths(
                words, "POST",
                body_template=template
            )
            if results:
                self.om.save_result("json", "json_fuzz",
                                    json.dumps(results, indent=2))

    def run_full_scan(self):
        """Run all fuzzing modules in sequence."""
        section("FULL SCAN MODE")
        info(f"Target : {C.CYAN}{self.target}{C.RESET}")
        info(f"Threads: {self.threads}  Timeout: {self.timeout}s  "
             f"Mode: {'DEEP' if self.deep else 'FAST'}")

        self.run_baseline()
        self.run_directory_fuzz()
        self.run_file_fuzz()
        self.run_param_fuzz("GET")
        self.run_param_fuzz("POST")
        self.run_method_fuzz()

        if self.domain:
            self.run_subdomain_fuzz()
            self.run_vhost_fuzz()

        success("Full scan complete!")
        info(f"Results in: {C.CYAN}{self.om.root}{C.RESET}")

# ─── Interactive Menu ─────────────────────────────────────────────────────────

class InteractiveMenu:
    """Clean interactive CLI menu."""

    def __init__(self):
        self.scanner: Optional[WebFuzz] = None
        self.config: dict = {
            "target":    "",
            "threads":   50,
            "timeout":   10,
            "deep":      False,
            "extensions": DEFAULT_EXTENSIONS,
            "domain":    "",
            "cookies":   "",
            "headers":   {},
        }

    def _prompt(self, msg: str, default: str = "") -> str:
        try:
            val = input(f"{C.CYAN}  >{C.RESET} {msg} [{default}]: ").strip()
            return val if val else default
        except (EOFError, KeyboardInterrupt):
            return default

    def _print_menu(self):
        print(f"""
{C.BOLD}{C.WHITE}╔══════════════════════════════════════╗
║         WebFuzz Main Menu            ║
╠══════════════════════════════════════╣
║{C.RESET} {C.YELLOW}[0]{C.RESET}  Set Target & Configure           {C.BOLD}{C.WHITE}║
║{C.RESET} {C.GREEN}[1]{C.RESET}  Directory Fuzzing                {C.BOLD}{C.WHITE}║
║{C.RESET} {C.GREEN}[2]{C.RESET}  File/Extension Fuzzing           {C.BOLD}{C.WHITE}║
║{C.RESET} {C.GREEN}[3]{C.RESET}  Recursive Fuzzing                {C.BOLD}{C.WHITE}║
║{C.RESET} {C.GREEN}[4]{C.RESET}  GET Parameter Fuzzing            {C.BOLD}{C.WHITE}║
║{C.RESET} {C.GREEN}[5]{C.RESET}  POST Parameter Fuzzing           {C.BOLD}{C.WHITE}║
║{C.RESET} {C.GREEN}[6]{C.RESET}  PUT Method Fuzzing               {C.BOLD}{C.WHITE}║
║{C.RESET} {C.GREEN}[7]{C.RESET}  HTTP Method Testing (All)        {C.BOLD}{C.WHITE}║
║{C.RESET} {C.GREEN}[8]{C.RESET}  Subdomain Fuzzing                {C.BOLD}{C.WHITE}║
║{C.RESET} {C.GREEN}[9]{C.RESET}  VHost Fuzzing                    {C.BOLD}{C.WHITE}║
║{C.RESET} {C.GREEN}[10]{C.RESET} Header Fuzzing                   {C.BOLD}{C.WHITE}║
║{C.RESET} {C.GREEN}[11]{C.RESET} Cookie Fuzzing                   {C.BOLD}{C.WHITE}║
║{C.RESET} {C.GREEN}[12]{C.RESET} JSON Body Fuzzing                {C.BOLD}{C.WHITE}║
║{C.RESET} {C.CYAN}[13]{C.RESET} Check Tools & Wordlists          {C.BOLD}{C.WHITE}║
║{C.RESET} {C.MAGENTA}[99]{C.RESET} Full Auto Scan                   {C.BOLD}{C.WHITE}║
║{C.RESET} {C.RED}[0]{C.RESET}  Configure / Change Target        {C.BOLD}{C.WHITE}║
║{C.RESET} {C.RED}[q]{C.RESET}  Quit                             {C.BOLD}{C.WHITE}║
╚══════════════════════════════════════╝{C.RESET}""")

    def configure(self):
        section("Configuration")
        t = self._prompt("Target URL (e.g. http://10.10.10.10)", self.config["target"])
        if t:
            self.config["target"] = t

        th = self._prompt("Threads", str(self.config["threads"]))
        try:
            self.config["threads"] = int(th)
        except ValueError:
            pass

        to = self._prompt("Timeout (seconds)", str(self.config["timeout"]))
        try:
            self.config["timeout"] = int(to)
        except ValueError:
            pass

        deep = self._prompt("Deep scan mode? (y/n)", "n")
        self.config["deep"] = deep.lower() == "y"

        dom = self._prompt("Domain (for subdomain/vhost)", self.config["domain"])
        if dom:
            self.config["domain"] = dom

        ck = self._prompt("Cookies (name=val; ...)", self.config["cookies"])
        if ck:
            self.config["cookies"] = ck

        ext = self._prompt("Custom extensions (comma-separated, or press Enter to keep defaults)", "")
        if ext:
            self.config["extensions"] = [e if e.startswith(".") else f".{e}"
                                          for e in ext.split(",")]

        if self.config["target"]:
            self.scanner = WebFuzz(self.config)
            success(f"Target set: {C.CYAN}{self.config['target']}{C.RESET}")
        else:
            error("No target set.")

    def _require_scanner(self) -> bool:
        if not self.scanner:
            warn("Set a target first (option 0)")
            return False
        return True

    def run(self):
        print_banner()
        ToolChecker.print_status()
        print()

        while True:
            if not _STOP_EVENT.is_set():
                self._print_menu()
            try:
                choice = input(f"\n{C.BOLD}WebFuzz{C.RESET} > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                warn("Exiting...")
                break

            if choice == "q":
                warn("Goodbye.")
                break
            elif choice == "0":
                self.configure()
            elif choice == "1":
                if self._require_scanner():
                    self.scanner.run_directory_fuzz()
            elif choice == "2":
                if self._require_scanner():
                    self.scanner.run_file_fuzz()
            elif choice == "3":
                if self._require_scanner():
                    d = self._prompt("Recursion depth", "2")
                    self.scanner.run_recursive_fuzz(int(d))
            elif choice == "4":
                if self._require_scanner():
                    self.scanner.run_param_fuzz("GET")
            elif choice == "5":
                if self._require_scanner():
                    self.scanner.run_param_fuzz("POST")
            elif choice == "6":
                if self._require_scanner():
                    path = self._prompt("Upload path", "/upload/test.txt")
                    self.scanner.run_put_fuzz(path)
            elif choice == "7":
                if self._require_scanner():
                    paths = self._prompt("Paths (comma-sep)", "/,/api,/admin").split(",")
                    self.scanner.run_method_fuzz([p.strip() for p in paths])
            elif choice == "8":
                if self._require_scanner():
                    dom = self._prompt("Domain", self.config.get("domain", ""))
                    self.scanner.run_subdomain_fuzz(dom)
            elif choice == "9":
                if self._require_scanner():
                    dom = self._prompt("Domain", self.config.get("domain", ""))
                    self.scanner.run_vhost_fuzz(dom)
            elif choice == "10":
                if self._require_scanner():
                    path = self._prompt("Path to fuzz headers on", "/")
                    self.scanner.run_header_fuzz(path)
            elif choice == "11":
                if self._require_scanner():
                    name = self._prompt("Cookie name", "session")
                    path = self._prompt("Path", "/")
                    self.scanner.run_cookie_fuzz(name, path)
            elif choice == "12":
                if self._require_scanner():
                    path = self._prompt("API endpoint", "/api")
                    tmpl = self._prompt("JSON template (use FUZZ)", '{"key": "FUZZ"}')
                    self.scanner.run_json_fuzz(path, tmpl)
            elif choice == "13":
                ToolChecker.print_status()
                section("Wordlist Discovery")
                we = WordlistEngine()
                cats = ["directory", "file", "subdomain", "vhost", "parameter"]
                for cat in cats:
                    wl = we.best(cat)
                    we.print_selected(cat, wl, True)
            elif choice == "99":
                if self._require_scanner():
                    self.scanner.run_full_scan()
            else:
                warn("Invalid option.")

# ─── Argument Parser ──────────────────────────────────────────────────────────

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webfuzz",
        description=f"WebFuzz v{VERSION} — Professional Web Fuzzing Tool (Legal PTLabs)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive menu
  python3 webfuzz.py

  # Quick directory scan
  python3 webfuzz.py -t http://10.10.10.10 --dir

  # Full auto scan (deep mode)
  python3 webfuzz.py -t http://10.10.10.10 --full --deep

  # Subdomain + vhost fuzzing
  python3 webfuzz.py -t http://10.10.10.10 --subdomain --vhost --domain target.htb

  # JSON body fuzzing with custom template
  python3 webfuzz.py -t http://10.10.10.10 --json --json-path /api/login \\
      --json-template '{"username":"FUZZ","password":"test"}'

  # Custom threads, timeout, cookies
  python3 webfuzz.py -t http://10.10.10.10 --dir -T 100 --timeout 15 \\
      --cookies "session=abc123"
        """
    )

    p.add_argument("-t",  "--target",     required=False, help="Target URL")
    p.add_argument(       "--domain",     help="Domain for subdomain/vhost fuzzing")
    p.add_argument("-T",  "--threads",    type=int, default=50, help="Thread count (default: 50)")
    p.add_argument(       "--timeout",    type=int, default=10, help="Request timeout seconds")
    p.add_argument(       "--deep",       action="store_true", help="Deep scan (larger wordlists)")
    p.add_argument("-x",  "--extensions", help="Comma-separated extensions for file fuzzing")
    p.add_argument(       "--cookies",    help="Cookie string: name=val; name2=val2")
    p.add_argument("-H",  "--header",     action="append", default=[],
                   metavar="Name:Value",  help="Custom header (repeatable)")

    modes = p.add_argument_group("Scan Modes")
    modes.add_argument("--dir",       action="store_true", help="Directory fuzzing")
    modes.add_argument("--files",     action="store_true", help="File/extension fuzzing")
    modes.add_argument("--recursive", action="store_true", help="Recursive directory fuzzing")
    modes.add_argument("--params",    action="store_true", help="GET+POST parameter fuzzing")
    modes.add_argument("--methods",   action="store_true", help="HTTP method testing (all)")
    modes.add_argument("--put",       action="store_true", help="PUT upload test")
    modes.add_argument("--subdomain", action="store_true", help="Subdomain enumeration")
    modes.add_argument("--vhost",     action="store_true", help="VHost fuzzing")
    modes.add_argument("--headers",   action="store_true", help="Header injection fuzzing")
    modes.add_argument("--cookies-fuzz", action="store_true", help="Cookie value fuzzing")
    modes.add_argument("--json",      action="store_true", help="JSON body fuzzing")
    modes.add_argument("--full",      action="store_true", help="Run all modules")

    advanced = p.add_argument_group("Advanced")
    advanced.add_argument("--put-path",       default="/upload/test.txt")
    advanced.add_argument("--json-path",      default="/api")
    advanced.add_argument("--json-template",  default='{"key": "FUZZ"}')
    advanced.add_argument("--cookie-name",    default="session")
    advanced.add_argument("--method-paths",   default="/,/api,/admin")
    advanced.add_argument("--recursion-depth", type=int, default=2)
    advanced.add_argument("--tools-check",    action="store_true",
                           help="Show tool/wordlist status and exit")

    return p


def main():
    print_banner()
    parser = build_argparser()
    args   = parser.parse_args()

    # No args → interactive menu
    if not args.target and not args.tools_check:
        InteractiveMenu().run()
        return

    if args.tools_check:
        ToolChecker.print_status()
        section("Wordlist Discovery")
        we = WordlistEngine()
        for cat in ["directory", "file", "subdomain", "vhost", "parameter"]:
            wl = we.best(cat)
            we.print_selected(cat, wl, True)
        return

    if not args.target:
        parser.print_help()
        sys.exit(1)

    # Parse extra headers
    custom_hdrs = {}
    for hdr in args.header:
        if ":" in hdr:
            k, v = hdr.split(":", 1)
            custom_hdrs[k.strip()] = v.strip()

    # Parse custom extensions
    extensions = DEFAULT_EXTENSIONS
    if args.extensions:
        extensions = [e if e.startswith(".") else f".{e}"
                      for e in args.extensions.split(",")]

    config = {
        "target":    args.target,
        "threads":   args.threads,
        "timeout":   args.timeout,
        "deep":      args.deep,
        "extensions": extensions,
        "domain":    args.domain or "",
        "cookies":   args.cookies or "",
        "headers":   custom_hdrs,
    }

    scanner = WebFuzz(config)
    scanner.run_baseline()

    if args.full:
        scanner.run_full_scan()
        return

    if args.dir:          scanner.run_directory_fuzz()
    if args.files:        scanner.run_file_fuzz()
    if args.recursive:    scanner.run_recursive_fuzz(args.recursion_depth)
    if args.params:
        scanner.run_param_fuzz("GET")
        scanner.run_param_fuzz("POST")
    if args.methods:
        paths = [p.strip() for p in args.method_paths.split(",")]
        scanner.run_method_fuzz(paths)
    if args.put:          scanner.run_put_fuzz(args.put_path)
    if args.subdomain:    scanner.run_subdomain_fuzz(args.domain)
    if args.vhost:        scanner.run_vhost_fuzz(args.domain)
    if args.headers:      scanner.run_header_fuzz()
    if args.cookies_fuzz: scanner.run_cookie_fuzz(args.cookie_name)
    if args.json:         scanner.run_json_fuzz(args.json_path, args.json_template)

    info(f"Done. Results: {C.CYAN}{scanner.om.root}{C.RESET}")


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
