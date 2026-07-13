"""Window feature extraction. Pure module: no aiokafka.

A window is every parsed log line one client_ip produced in one minute.
Features describe the *content mix* (per-family template counts, auth-failure
and 4xx ratios, template diversity) — the same vector the XGBoost model was
trained on (training/train_sentinel.py imports FEATURE_NAMES from here, so
train/serve can't drift).
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Sequence

from drain3 import TemplateMiner

from .logparse import ParsedLine, mine
from .rules import AUTH_FAIL, BENIGN_FAMILIES, OTHER, SCANNER, SCHEMA_REJECT, SQLI, TRAVERSAL, classify

# Order is the model's feature order — append-only; retrain on any change.
FEATURE_NAMES = (
    "window_events",
    "distinct_templates",
    "n_sqli",
    "n_traversal",
    "n_auth_fail",
    "n_scanner",
    "n_schema_reject",
    "n_other",
    "n_suspicious_other",
    "benign_ratio",
    "auth_fail_ratio",
    "err_4xx_ratio",
    "max_auth_attempt",
)

_ATTEMPT_RE = re.compile(r"\(attempt (\d+)\)")


@dataclass(frozen=True, slots=True)
class AnalyzedLine:
    parsed: ParsedLine
    family: str
    level: int
    cluster_id: int


def analyze_line(parsed: ParsedLine, miner: TemplateMiner) -> AnalyzedLine:
    family, level = classify(parsed)
    return AnalyzedLine(parsed, family, level, mine(miner, parsed))


def window_features(lines: Sequence[AnalyzedLine]) -> dict:
    """Feature dict for one window: FEATURE_NAMES keys (model vector) plus
    `template_counts` (per-family counts for score docs / reasons)."""
    n = len(lines)
    counts: Counter[str] = Counter(line.family for line in lines)
    benign_n = sum(counts[f] for f in BENIGN_FAMILIES)
    suspicious_other = sum(
        1 for line in lines if line.family == OTHER and line.level == 1
    )
    err_4xx = sum(1 for line in lines if line.parsed.code >= 400)
    max_attempt = 0
    for line in lines:
        if line.family == AUTH_FAIL:
            m = _ATTEMPT_RE.search(line.parsed.msg)
            if m:
                max_attempt = max(max_attempt, int(m.group(1)))
    return {
        "window_events": float(n),
        "distinct_templates": float(len({line.cluster_id for line in lines})),
        "n_sqli": float(counts[SQLI]),
        "n_traversal": float(counts[TRAVERSAL]),
        "n_auth_fail": float(counts[AUTH_FAIL]),
        "n_scanner": float(counts[SCANNER]),
        "n_schema_reject": float(counts[SCHEMA_REJECT]),
        "n_other": float(counts[OTHER]),
        "n_suspicious_other": float(suspicious_other),
        "benign_ratio": benign_n / n if n else 0.0,
        "auth_fail_ratio": counts[AUTH_FAIL] / n if n else 0.0,
        "err_4xx_ratio": err_4xx / n if n else 0.0,
        "max_auth_attempt": float(max_attempt),
        "template_counts": {fam: cnt for fam, cnt in sorted(counts.items())},
    }
