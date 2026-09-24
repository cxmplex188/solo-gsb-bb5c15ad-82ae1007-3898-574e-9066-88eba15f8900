"""Path-based risk gate over already-stored audit records.

Given a set of persisted audit IDs and an ordered list of file-path rules,
each record is checked against the highest risk it is allowed to carry.
Rule templates are glob-like path patterns split on ``/``:

* ``*``  matches any run of characters within a *single* segment (it can
  never cross a ``/``), so both ``src/*`` and ``*.py`` work as expected;
* ``**`` matches zero or more whole segments (it may cross ``/``);
* every other character, including ``?`` / ``[`` / ``.``, is literal.

When several rules match a file path the winner is chosen by, in order:

1. the greatest number of fixed segments -- a segment counts as fixed
   unless it is exactly ``**``, so a specific rule always wins over a
   wildcard-spanning one;
2. the greatest total number of segments in the template, so the more
   specific (longer) pattern wins;
3. the rule's position in the request, so earlier rules win.

Records without a file name, and records whose path no rule matches, fall
back to the request's default threshold.  Everything here is read-only:
records are never created, modified or deleted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

RISK_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class GateRule:
    """One ordered path rule: a path template plus the risk it allows."""

    index: int
    template: str
    max_risk: str
    segments: tuple[str, ...]
    fixed_segments: int


def compile_rules(rules: list[tuple[str, str]]) -> list[GateRule]:
    """Turn ``(template, max_risk)`` pairs (in request order) into rules."""
    compiled: list[GateRule] = []
    for index, (template, max_risk) in enumerate(rules):
        segments = tuple(template.split("/"))
        fixed = sum(1 for segment in segments if segment != "**")
        compiled.append(GateRule(
            index=index,
            template=template,
            max_risk=max_risk,
            segments=segments,
            fixed_segments=fixed,
        ))
    return compiled


def _segment_regex(piece: str) -> re.Pattern:
    """Compile one non-``**`` template segment: ``*`` matches within the
    segment, everything else is literal."""
    out = ["(?s:"]
    for ch in piece:
        if ch == "*":
            out.append(".*")
        else:
            out.append(re.escape(ch))
    out.append(")\\Z")
    return re.compile("".join(out))


def _match_segments(pattern: tuple[str, ...], path: tuple[str, ...]) -> bool:
    """Match a split template against split path segments.

    ``*`` matches any characters within one segment and ``**`` matches
    zero or more whole segments; everything else is literal.
    """
    segment_match = [
        None if piece == "**" else _segment_regex(piece) for piece in pattern
    ]

    # DFS over the template; ** may consume 0..n remaining segments.
    def walk(pi: int, si: int) -> bool:
        while pi < len(pattern):
            matcher = segment_match[pi]
            if matcher is None:  # "**"
                # collapse adjacent ** entries (they consume jointly)
                while pi < len(pattern) and segment_match[pi] is None:
                    pi += 1
                if pi == len(pattern):
                    return True  # trailing ** swallows everything left
                for consumed in range(len(path) - si + 1):
                    if walk(pi, si + consumed):
                        return True
                return False
            if si >= len(path) or matcher.fullmatch(path[si]) is None:
                return False
            pi += 1
            si += 1
        return si == len(path)

    return walk(0, 0)


def pattern_matches(template: str, path: str) -> bool:
    """Public helper: does a ``/``-split template match a ``/``-split path?"""
    return _match_segments(tuple(template.split("/")), tuple(path.split("/")))


def select_rule(
    path: str, rules: list[GateRule]
) -> Optional[GateRule]:
    """Pick the winning matching rule for *path*, or ``None`` on no match."""
    segments = tuple(path.split("/"))
    winner: Optional[GateRule] = None
    for rule in rules:
        if not _match_segments(rule.segments, segments):
            continue
        if winner is None:
            winner = rule
            continue
        if rule.fixed_segments != winner.fixed_segments:
            if rule.fixed_segments > winner.fixed_segments:
                winner = rule
        elif len(rule.segments) != len(winner.segments):
            if len(rule.segments) > len(winner.segments):
                winner = rule
        # equal on both counts: keep the earlier request rule (winner)
    return winner


def evaluate_record(
    record: dict, rules: list[GateRule], default_max_risk: str
) -> dict:
    """Apply the gate to one stored audit record (read-only projection)."""
    filename = record.get("filename")
    matched: Optional[GateRule] = (
        select_rule(filename, rules) if filename else None
    )

    if matched is not None:
        source = "rule"
        max_risk = matched.max_risk
        template = matched.template
        rule_index = matched.index
    else:
        source = "default"
        max_risk = default_max_risk
        template = None
        rule_index = None

    actual_risk = record["risk_level"]
    passed = RISK_ORDER[actual_risk] <= RISK_ORDER[max_risk]

    return {
        "id": record["id"],
        "filename": filename,
        "actual_risk": actual_risk,
        "max_risk": max_risk,
        "threshold_source": source,
        "matched": matched is not None,
        "matched_rule_index": rule_index,
        "matched_template": template,
        "passed": passed,
    }


def gate_records(
    records: list[dict],
    rules: list[tuple[str, str]],
    default_max_risk: str,
) -> dict:
    """Evaluate a list of stored records and summarise the overall verdict."""
    compiled = compile_rules(rules)
    items = [evaluate_record(record, compiled, default_max_risk)
             for record in records]
    highest = max(
        (item["actual_risk"] for item in items),
        key=lambda level: RISK_ORDER[level],
        default="info",
    )
    passed = all(item["passed"] for item in items)
    return {
        "default_max_risk": default_max_risk,
        "rules": [
            {"index": index, "template": template, "max_risk": max_risk}
            for index, (template, max_risk) in enumerate(rules)
        ],
        "passed": passed,
        "result": "passed" if passed else "failed",
        "checked": len(items),
        "passed_count": sum(1 for item in items if item["passed"]),
        "failed_count": sum(1 for item in items if not item["passed"]),
        "highest_risk": highest,
        "items": items,
    }
