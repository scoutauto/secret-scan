#!/usr/bin/env python3
"""secret-scan: find likely secrets in files before you commit or share them.

Usage: python3 secret_scan.py PATH [PATH ...]
Exit code 0 = nothing found, 1 = findings, 2 = usage error.
Standard library only. Pattern-based, so expect some false positives.
"""
import os
import re
import sys

PATTERNS = {
    "AWS access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Stripe live key": re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Generic assignment": re.compile(
        r"(?i)\b(api[_-]?key|secret|password|token)\b\s*[:=]\s*['\"]?([^\s'\"]{12,})"
    ),
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}
MAX_BYTES = 1_000_000


def scan_file(path):
    findings = []
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES)
    except OSError:
        return findings
    if b"\x00" in data:  # skip binaries
        return findings
    text = data.decode("utf-8", errors="replace")
    for lineno, line in enumerate(text.splitlines(), 1):
        for name, pat in PATTERNS.items():
            if pat.search(line):
                findings.append((path, lineno, name))
    return findings


def walk(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for f in files:
                    yield os.path.join(root, f)
        elif os.path.isfile(p):
            yield p


def main(argv):
    if not argv:
        print(__doc__.strip())
        return 2
    total = 0
    for path in walk(argv):
        for fpath, lineno, name in scan_file(path):
            print(f"{fpath}:{lineno}: {name}")
            total += 1
    print(f"{total} finding(s)")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
