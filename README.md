<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey?style=for-the-badge" />
  <img src="https://img.shields.io/github/stars/aabderrafie/webfuzz?style=for-the-badge" />
</p>

```
 ██╗    ██╗███████╗██████╗ ███████╗██╗   ██╗███████╗███████╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██║   ██║╚════██║╚════██║
 ██║ █╗ ██║█████╗  ██████╔╝█████╗  ██║   ██║    ██╔╝    ██╔╝
 ██║███╗██║██╔══╝  ██╔══██╗██╔══╝  ██║   ██║   ██╔╝    ██╔╝
 ╚███╔███╔╝███████╗██████╔╝██║     ╚██████╔╝   ██║     ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝      ╚═════╝    ╚═╝     ╚═╝
```
# WebFuzz — Professional Web Fuzzing Tool

> **All-in-one web fuzzer for legal penetration testing labs** (HackTheBox, TryHackMe, CTFs & authorized engagements).

WebFuzz is a pure-Python CLI tool that automates directory, file, parameter, subdomain, vhost, header, cookie, and JSON body fuzzing. It intelligently discovers and ranks installed wordlists, wraps industry tools like **ffuf** and **gobuster** when available, and falls back to a fast built-in HTTP engine when they're not.

---

## Features

| Module                           | Description                                                         |
| -------------------------------- | ------------------------------------------------------------------- |
| **Directory Fuzzing**            | Discover hidden directories with smart wordlist selection           |
| **File / Extension Fuzzing**     | Brute-force files with 28+ common extensions                        |
| **Recursive Fuzzing**            | Crawl into discovered directories automatically                     |
| **GET & POST Parameter Fuzzing** | Find hidden parameters on endpoints                                 |
| **HTTP Method Testing**          | Test OPTIONS, PUT, DELETE, PATCH, HEAD on paths                     |
| **PUT Upload Testing**           | Attempt file uploads via PUT method                                 |
| **Subdomain Enumeration**        | DNS brute-force via gobuster/ffuf                                   |
| **VHost Fuzzing**                | Discover virtual hosts via Host header manipulation                 |
| **Header Injection Fuzzing**     | Test X-Forwarded-For, X-Original-URL, etc.                          |
| **Cookie Fuzzing**               | Fuzz cookie values for IDOR / auth bypass                           |
| **JSON Body Fuzzing**            | Fuzz API endpoints with custom JSON templates                       |
| **Smart Baseline Detection**     | Auto-detect 404 response patterns to reduce false positives         |
| **Wordlist Auto-Discovery**      | Scores and ranks SecLists / Kali wordlists automatically            |
| **Auto Escalation**              | If a scan returns 0 results, escalates to a larger wordlist         |
| **Tool Wrapping**                | Uses ffuf / gobuster when installed; pure-Python fallback otherwise |
| **Structured Output**            | Organized results directory with logs, JSON, and metadata           |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/aabderrafie/webfuzz.git
cd webfuzz
```

### 2. Requirements

WebFuzz uses **only the Python 3 standard library** — no `pip install` needed.

- **Python 3.8+** (required)

### 3. (Recommended) Install external tools & wordlists

For maximum power, install these system packages:

```bash
# Kali / Debian / Ubuntu
sudo apt install ffuf gobuster curl seclists

# macOS (Homebrew)
brew install ffuf gobuster curl
```

> Without ffuf/gobuster, WebFuzz falls back to its built-in multi-threaded HTTP engine.

### 4. Make it executable (optional)

```bash
chmod +x webfuzz.py
```

---

## Quick Start

### Interactive Mode (recommended for beginners)

```bash
python3 webfuzz.py
```

This launches a menu-driven interface where you configure the target and select scan modules interactively.

### CLI Mode

```bash
# Directory fuzzing
python3 webfuzz.py -t http://10.10.10.10 --dir

# Full auto scan (all modules)
python3 webfuzz.py -t http://10.10.10.10 --full

# Deep mode (uses larger wordlists)
python3 webfuzz.py -t http://10.10.10.10 --full --deep

# Subdomain + VHost fuzzing
python3 webfuzz.py -t http://10.10.10.10 --subdomain --vhost --domain target.htb

# JSON body fuzzing with custom template
python3 webfuzz.py -t http://10.10.10.10 --json --json-path /api/login \
    --json-template '{"username":"FUZZ","password":"test"}'

# Custom threads, timeout, and cookies
python3 webfuzz.py -t http://10.10.10.10 --dir -T 100 --timeout 15 \
    --cookies "session=abc123"
```

---

## Usage

```
usage: webfuzz [-h] [-u TARGET] [-w WORDLIST] [--domain DOMAIN] [-T THREADS]
               [--timeout TIMEOUT] [--deep] [-x EXTENSIONS]
               [--cookies COOKIES] [-H Name:Value] [-d] [-F] [-r] [-p] [-m]
               [-P] [-s] [-v] [-hd] [-c] [-j] [-f] [--put-path PUT_PATH]
               [--json-path JSON_PATH] [--json-template JSON_TEMPLATE]
               [--cookie-name COOKIE_NAME] [--method-paths METHOD_PATHS]
               [--recursion-depth RECURSION_DEPTH] [--tools-check]

options:
  -h, --help            show this help message and exit
  -u, --target TARGET   Target URL
  -w, --wordlist WORDLIST
                        Custom wordlist path
  --domain DOMAIN       Domain for subdomain/vhost fuzzing
  -T, --threads THREADS
                        Thread count (default: 50)
  --timeout TIMEOUT     Request timeout seconds
  --deep                Deep scan (larger wordlists)
  -x, --extensions EXTENSIONS
                        Comma-separated extensions for file fuzzing
  --cookies COOKIES     Cookie string: name=val; name2=val2
  -H, --header Name:Value
                        Custom header (repeatable)

Scan Modes:
  -d, --dir             Directory fuzzing
  -F, --files           File/extension fuzzing
  -r, --recursive       Recursive directory fuzzing
  -p, --params          GET+POST parameter fuzzing
  -m, --methods         HTTP method testing (all)
  -P, --put             PUT upload test
  -s, --subdomain       Subdomain enumeration
  -v, --vhost           VHost fuzzing
  -hd, --headers        Header injection fuzzing
  -c, --cookies-fuzz    Cookie value fuzzing
  -j, --json            JSON body fuzzing
  -f, --full            Run all modules
```

---

## Output Structure

Results are saved in a timestamped directory:

```
results/
└── http_10_10_10_10_20260221_143022/
    ├── directories/     # Directory & recursive scan results
    ├── files/           # File/extension scan results
    ├── parameters/      # GET/POST parameter results
    ├── methods/         # HTTP method test results
    ├── subdomains/      # Subdomain enumeration results
    ├── vhosts/          # Virtual host fuzzing results
    ├── headers/         # Header injection & cookie fuzz results
    ├── json/            # JSON body fuzzing results
    └── logs/            # Session log (scan.log)
```



