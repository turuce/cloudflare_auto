import requests

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import ipaddress
import json
import logging
import os
import re
import sys
import time
from typing import Any, Callable, Iterable
from urllib.parse import unquote_plus

import yaml

__version__ = "0.1.0"

API_BASE = "https://api.cloudflare.com/client/v4"
TAG = "cf_autoguard"
COMMENT_TIME_FMT = "%Y-%m-%dT%H:%MZ"
MAX_WINDOW_MINUTES = 1440  # adaptive datasets: max 24h per query

log = logging.getLogger("cf_auto_guard")

Net = ipaddress.IPv4Network | ipaddress.IPv6Network

#default configuration
DEFAULTS: dict[str, Any] = {
    "window_minutes": 20,
    "hosts": [],  # empty = all hosts in the zone
    "ipv6_prefix": 64,
    "allowlist": {"cidrs": [], "asns": []},
    "thresholds": {
        "block_score": 100,
        "watch_score": 50,
        "rate_per_minute": 300,
        "error_ratio": 0.6,
        "error_ratio_min_requests": 60,
        # 403 deliberately excluded: cf-guard's own blocks return 403
        "error_statuses": [400, 401, 404, 405],
        "login_failures": 15,
        "login_failure_statuses": [401, 429],
        "waf_min_events": 3,
    },
    "scoring": {
        "weights": {
            "signature_hit": 60,   # per distinct attack class (sqli, xss, ...)
            "scanner_ua": 100,     # known offensive tooling user agent
            "suspicious_ua": 15,
            "empty_ua": 20,
            "sensitive_path": 25,  # per distinct sensitive path probed
            "waf_event": 10,       # per WAF block/challenge event
            "high_rate": 50,
            "error_ratio": 40,
            "login_abuse": 70,
        },
        "caps": {"sensitive_path": 100, "waf_event": 80},
    },
    "waf": {
        "count_actions": [
            "block", "challenge", "jschallenge", "managed_challenge",
            "challenge_failed", "jschallenge_failed", "managed_challenge_failed",
        ],
        # ID of the WAF rule that enforces the cf-guard list, so cf-guard
        # does not re-score traffic it already blocked.
        "ignore_rule_ids": [],
    },
    "blocking": {
        "ttl_hours": 24,        # behavioural detections (rate, errors, WAF)
        "ttl_hours_hard": 168,  # payload signatures / scanner tooling
        "max_new_per_run": 50,
        "abort_if_more_than": 300,  # circuit breaker: likely misconfiguration
        "max_list_items": 10000,
    },
    "login_paths": [
        r"/login\b", r"/signin\b", r"/sign-in\b", r"/wp-login\.php",
        r"/user/login", r"/account/login", r"/api/(v\d+/)?auth",
    ],
    "sensitive_paths": [
        r"/\.env(\.|$|/)", r"/\.git(/|$)", r"/\.svn/", r"/\.hg/", r"/\.aws/",
        r"/\.ssh/", r"/\.ds_store$", r"/\.htaccess$", r"/\.htpasswd$",
        r"wp-config\.php", r"/phpmyadmin", r"/pma/", r"/adminer(\.php)?$",
        r"/vendor/phpunit/", r"/cgi-bin/", r"/actuator(/|$)", r"/server-status$",
        r"/boaform/", r"/hnap1", r"/xmlrpc\.php$", r"/\.vscode/", r"/config\.(json|yml|yaml|php)$",
        r"\.(bak|old|orig|swp|sql|sqlite|tar|tar\.gz|tgz|zip|7z)$",
        r"/(backup|dump|db|database)\.", r"/shell\.php", r"/cmd\.php", r"/eval-stdin\.php",
    ],
    "scanner_user_agents": [
        r"sqlmap", r"nikto", r"nuclei", r"masscan", r"zgrab", r"nmap", r"dirbuster",
        r"gobuster", r"feroxbuster", r"\bffuf\b", r"wpscan", r"acunetix", r"netsparker",
        r"nessus", r"openvas", r"hydra", r"burp", r"jaeles", r"wfuzz", r"arachni",
        r"commix", r"xsstrike", r"zaproxy|owasp zap", r"interactsh", r"censysinspect",
    ],
    "suspicious_user_agents": [
        r"python-requests", r"python-urllib", r"aiohttp", r"go-http-client",
        r"^curl/", r"^wget/", r"libwww-perl", r"java/\d", r"okhttp", r"httpclient",
        r"scrapy", r"headlesschrome", r"phantomjs",
    ],
    "signatures": {
        "sqli": (
            r"union[\s+/*]*(all[\s+/*]*)?select|(extractvalue|updatexml)\s*\(|"
            r"sleep\s*\(\s*\d|benchmark\s*\(|waitfor[\s+]+delay|information_schema|"
            r"order[\s+]+by[\s+]+\d+[\s+]*(--|#|/\*)|/\*\*/\s*(and|or|union|select)\b|"
            r"['\")]\s*(and|or)\s*['\"(]?\d+\s*=\s*\d+"
        ),
        "xss": (
            r"<\s*script|javascript\s*:|\bon(error|load|mouseover|focus)\s*=|"
            r"<\s*(svg|img|iframe)[^>]*\bon\w+\s*=|document\.cookie|alert\s*\("
        ),
        "traversal": r"\.\./|\.\.\\|/etc/(passwd|shadow|hosts)|/proc/self/|win\.ini|boot\.ini",
        "cmdi": r"[;|`]\s*(cat|wget|curl|nc|ncat|bash|sh|id|whoami|uname|ping)\b|\$\(\s*(id|whoami|curl|wget)",
        "jndi": r"\$\{\s*(jndi|\$\{|lower:|upper:|env:)",
        "ssti": r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}|\$\{\s*\d+\s*\*\s*\d+\s*\}|<%=\s*\d+\s*\*\s*\d+",
        "ssrf": r"169\.254\.169\.254|metadata\.google\.internal|file:///|gopher://|dict://",
    },
}

HARD_REASONS_PREFIX = ("sig:", "scanner_ua")

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def safe(text: Any, limit: int = 160) -> str:
    """Neutralise control characters in attacker-controlled strings (log injection)."""
    return _CTRL.sub("?", str(text))[:limit]


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(ts: dt.datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")

def deep_merge(base: dict, override: dict | None) -> dict:
    out = dict(base)
    for key, val in (override or {}).items():
        if isinstance(val, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], val)
        else:
            out[key] = val
    return out

def normalise_payload(path: str | None, query: str | None = None) -> str:
    """Recursively URL-decode (defeats double encoding) and lowercase."""
    s = path or ""
    if query:
        s += query if query.startswith("?") else "?" + query
    for _ in range(3):
        decoded = unquote_plus(s)
        if decoded == s:
            break
        s = decoded
    return s.lower()

def subject_for(ip: str, v6_prefix: int = 64) -> Net:
    """Blocking subject: IPv4 /32, IPv6 aggregated to a /64 (attackers rotate within it)."""
    addr = ipaddress.ip_address(ip.strip())
    if addr.version == 4:
        return ipaddress.ip_network(f"{addr}/32")
    return ipaddress.ip_network(f"{addr}/{v6_prefix}", strict=False)

def subject_str(net: Net) -> str:
    if net.version == 4 and net.prefixlen == 32:
        return str(net.network_address)
    return str(net)

def compile_any(patterns: Iterable[str]) -> re.Pattern | None:
    patterns = [p for p in patterns if p]
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.I) if patterns else None

def make_comment(expires: dt.datetime, score: int, reasons: Iterable[str]) -> str:
    return f"{TAG}|exp={expires.strftime(COMMENT_TIME_FMT)}|s={score}|r={','.join(reasons)}"[:200]
