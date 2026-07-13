"""Level-0 rule pre-filter + template-family classification. Pure module.

Every parsed line is assigned a (family, level) verdict:

    level 2  unambiguous malicious — SQL metacharacters in the query, `../`
             traversal, sensitive-file / scanner probes. One hit is enough
             evidence on its own; no model needed.
    level 1  suspicious — a lone auth failure (user typo or stuffing?), an
             unknown template answering 4xx. The windowed model decides.
    level 0  benign — the generator's pinned endpoint families, plus
             schema-reject lines (malformed traffic is ARGUS's niche).

Families mirror the log families pinned in docs/architecture.md and rendered
by services/mock-lti/app/generator.py — that file carries a matching warning
to notify this service when they change (then retrain via
training/train_sentinel.py and revisit these patterns).

The window-level bands derived from these verdicts (window_rule_level) are
also the training labels, so the "suspicious" middle class is reproducible
from code, not from manual labeling.
"""
from __future__ import annotations

import re
from typing import Mapping

from .logparse import ParsedLine

# Attack families (level 2 signatures live in the path).
SQLI = "sqli_probe"
TRAVERSAL = "path_traversal"
SCANNER = "scanner_probe"
AUTH_FAIL = "auth_failure"  # level 1 per line; a storm upgrades the window

LEVEL2_FAMILIES = (SQLI, TRAVERSAL, SCANNER)

# Benign families (structure-matched; values vary, structure doesn't).
BENIGN_FAMILIES = ("route", "declined", "balance", "status", "settlement")
SCHEMA_REJECT = "schema_reject"
OTHER = "other"

_TRAVERSAL_RE = re.compile(r"(?i)(\.\./|\.\.%2f|%2e%2e)")
# Quotes, statement separators, and comment/UNION markers never appear in the
# benign endpoint families, so any of them in a path+query is a signature.
_SQLI_RE = re.compile(r"(?i)('|%27|;|%3b|--|\bunion[\s+]+select\b|\bdrop[\s+]+table\b)")
# Dotfile access, PHP endpoints on a non-PHP stack, common admin-panel probes.
_SCANNER_RE = re.compile(r"(?i)(^/\.|/\.git\b|\.php\b|/phpmyadmin|/actuator/|^/wp-)")

_BALANCE_RE = re.compile(r"^/api/v1/accounts/[^/?]+/balance$")
_STATUS_RE = re.compile(r"^/api/v1/transactions/[^/?]+/status$")
_SETTLEMENT_RE = re.compile(r"^/api/v1/settlements/\w+$")
_ROUTE_PATH = "/api/v1/transactions/route"


def classify(line: ParsedLine) -> tuple[str, int]:
    """Verdict for one line: (family, level)."""
    path = line.path
    if _TRAVERSAL_RE.search(path):
        return TRAVERSAL, 2
    if _SQLI_RE.search(path):
        return SQLI, 2
    if _SCANNER_RE.search(path):
        return SCANNER, 2
    if line.code == 401 or line.msg.startswith("authentication failed"):
        return AUTH_FAIL, 1
    if path == _ROUTE_PATH:
        if line.code == 402:
            return "declined", 0
        if line.code == 400:
            return SCHEMA_REJECT, 0
        return "route", 0
    if _BALANCE_RE.match(path):
        return "balance", 0
    if _STATUS_RE.match(path):
        return "status", 0
    if _SETTLEMENT_RE.match(path):
        return "settlement", 0
    # Unknown template: a 4xx/5xx answer smells like probing; a 2xx is most
    # likely a benign endpoint this ruleset simply doesn't know yet.
    return OTHER, 1 if line.code >= 400 else 0


def window_rule_level(feats: Mapping[str, float], auth_fail_storm: int) -> int:
    """Rule verdict for a whole (client_ip, minute) window, computed from the
    extracted features. Shared by runtime scoring and training labels."""
    if feats["n_sqli"] or feats["n_traversal"] or feats["n_scanner"]:
        return 2
    if feats["n_auth_fail"] >= auth_fail_storm:
        return 2
    if feats["n_auth_fail"] or feats["n_suspicious_other"]:
        return 1
    return 0
