"""Gateway log-line parsing + Drain3 template mining. Pure module: no aiokafka.

The generator renders one combined access/app line per event
(docs/architecture.md#attack-modes):

    <ip> - <payer> [<ts>] "<METHOD> <path> HTTP/1.1" <code> <bytes> <lat>ms "<msg>"

A strict regex lifts the structured fields; the content (method, path, code,
message) then goes through Drain3 with aggressive masking (IPs, entity ids,
hex ids, numbers) so every downstream signal — rule matching, per-template
counts, distinct-template features — is computed over stable *templates*,
never over incidental values like a particular payer id or attempt number.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

# The path is non-greedy up to the literal ` HTTP/1.1` so SQLi payloads with
# spaces/quotes inside the request line still parse.
_LOG_RE = re.compile(
    r'^(?P<ip>\S+) - (?P<payer>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>.*?) HTTP/1\.1" '
    r'(?P<code>\d{3}) (?P<nbytes>\d+) (?P<lat>\d+)ms "(?P<msg>.*)"$'
)


@dataclass(frozen=True, slots=True)
class ParsedLine:
    ip: str
    payer: str | None
    method: str
    path: str
    code: int
    nbytes: int
    latency_ms: int
    msg: str


def parse_log_line(raw: str) -> ParsedLine | None:
    m = _LOG_RE.match(raw)
    if m is None:
        return None
    payer = m["payer"]
    return ParsedLine(
        ip=m["ip"],
        payer=None if payer == "-" else payer,
        method=m["method"],
        path=m["path"],
        code=int(m["code"]),
        nbytes=int(m["nbytes"]),
        latency_ms=int(m["lat"]),
        msg=m["msg"],
    )


def template_content(line: ParsedLine) -> str:
    """The string Drain3 mines: request shape + outcome, no envelope noise."""
    return f'{line.method} {line.path} {line.code} "{line.msg}"'


def build_miner() -> TemplateMiner:
    """In-memory Drain3 miner (no persistence: with masking, templates
    re-converge within seconds of a restart). Mask order matters — entity ids
    must go before the generic number mask or `merchant-0042` degrades to
    `merchant-<NUM>` vs `<ENTITY>` depending on tokenization."""
    cfg = TemplateMinerConfig()
    cfg.masking_instructions = [
        MaskingInstruction(r"\b(?:merchant|wallet-user|bank)-\d+\b", "ENTITY"),
        MaskingInstruction(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "IP"),
        MaskingInstruction(r"\b[0-9a-f]{8,}\b", "HEX"),
        MaskingInstruction(r"\b\d+\b", "NUM"),
    ]
    cfg.drain_sim_th = 0.4
    cfg.drain_depth = 4
    return TemplateMiner(config=cfg)


def mine(miner: TemplateMiner, line: ParsedLine) -> int:
    """Feed one parsed line to the miner; returns its template cluster id."""
    result = miner.add_log_message(template_content(line))
    return int(result["cluster_id"])
