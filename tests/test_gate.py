"""Tests for the path-based risk gate (POST /api/v1/audits/gate)."""

import pytest

from app.gate import pattern_matches, select_rule, compile_rules, gate_records

LRE = "‪"
RLO = "‮"
PDF = "‬"
LRI = "⁦"
LRM = "‎"


def _post(client, text, filename=None):
    return client.post(
        "/api/v1/audits", json={"text": text, "filename": filename}
    )


def _gate(client, ids, default_max_risk, rules=None):
    return client.post(
        "/api/v1/audits/gate",
        json={
            "ids": ids,
            "default_max_risk": default_max_risk,
            "rules": rules or [],
        },
    )


# ---------------------------------------------------------------------------
# Pattern matcher (unit-level)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "template,path",
    [
        ("a/b/c", "a/b/c"),
        ("*", "anything"),
        ("src/*", "src/app.py"),
        ("*.py", "app.py"),
        ("src/*.py", "src/app.py"),
        ("a/*/c", "a/b/c"),
        ("**", "a/b/c"),
        ("**/app.py", "app.py"),
        ("**/app.py", "src/app.py"),
        ("src/**", "src"),
        ("src/**", "src/app.py"),
        ("src/**", "src/a/b/c/app.py"),
        ("src/**/*.py", "src/app.py"),
        ("src/**/*.py", "src/lib/app.py"),
        ("src/**/*.py", "src/a/b/c/app.py"),
        ("a/**/z", "a/z"),
        ("a/**/z", "a/b/c/z"),
        ("a/**/b/**/c", "a/x/b/y/z/c"),
        ("**/**", "a/b"),
        ("a.b", "a.b"),
        ("a?b", "a?b"),
    ],
)
def test_pattern_matches(template, path):
    assert pattern_matches(template, path) is True


@pytest.mark.parametrize(
    "template,path",
    [
        ("a/b/c", "a/x/c"),
        ("*", "a/b"),
        ("src/*", "src/lib/app.py"),
        ("*.py", "src/app.py"),
        ("src/*.py", "src"),
        ("src/*.py", "src/app.txt"),
        ("a/*/c", "a/b/x/c"),
        ("**/app.py", "src/app.txt"),
        ("src/**", "other/app.py"),
        ("a/*", "a"),
        ("a/**/z", "a/b/c"),
        ("a/**/b/**/c", "a/x/y/z/c"),
        ("a.b", "axb"),
        ("a?b", "axb"),
    ],
)
def test_pattern_does_not_match(template, path):
    assert pattern_matches(template, path) is False


def test_star_matches_within_segment_not_across_slashes():
    # "*" never crosses a segment boundary
    assert pattern_matches("*", "") is True
    assert pattern_matches("*", "a") is True
    assert pattern_matches("*", "a/b") is False


def test_double_star_adjacent_entries_collapse():
    assert pattern_matches("a/**/**/z", "a/b/c/z")
    assert pattern_matches("a/**/**/z", "a/z")


# ---------------------------------------------------------------------------
# Rule selection tie-breaks (unit-level)
# ---------------------------------------------------------------------------

def test_select_rule_most_fixed_segments_wins():
    # "src/**" has one fixed segment ("src"); "**" has zero.
    rules = compile_rules([("**", "low"), ("src/**", "critical")])
    assert select_rule("src/app.py", rules).max_risk == "critical"


def test_select_rule_single_star_is_fixed_double_star_is_not():
    # "a/*/z" has 3 fixed segments; "a/**/z" has 2, even though both match.
    rules = compile_rules([("a/**/z", "low"), ("a/*/z", "high")])
    chosen = select_rule("a/b/z", rules)
    assert chosen.template == "a/*/z"
    assert chosen.max_risk == "high"


def test_select_rule_total_segment_count_is_second_tiebreak():
    # Equal fixed segments (none is "**"); longer template wins regardless
    # of request order.
    rules = compile_rules([("a/*/b", "low"), ("a/*", "high")])
    chosen = select_rule("a/x/b", rules)
    assert chosen.template == "a/*/b"


def test_select_rule_request_order_is_final_tiebreak():
    rules = compile_rules([("a/*", "low"), ("a/x", "high")])
    chosen = select_rule("a/x", rules)
    assert chosen.template == "a/*"  # same fixed count, same length
    assert chosen.max_risk == "low"


def test_select_rule_returns_none_when_nothing_matches():
    rules = compile_rules([("src/**", "low")])
    assert select_rule("docs/readme.md", rules) is None


def test_select_rule_empty_rule_list():
    assert select_rule("a/b", compile_rules([])) is None


# ---------------------------------------------------------------------------
# gate_records projection
# ---------------------------------------------------------------------------

def _record(audit_id, filename, risk_level):
    return {"id": audit_id, "filename": filename, "risk_level": risk_level}


def test_gate_records_default_threshold_for_unmatched_and_nameless():
    records = [
        _record(1, "docs/a.md", "high"),
        _record(2, None, "low"),
        _record(3, "", "low"),
    ]
    result = gate_records(records, rules=[("src/**", "critical")],
                          default_max_risk="medium")
    assert result["passed"] is False
    assert result["result"] == "failed"
    assert result["checked"] == 3
    assert result["passed_count"] == 2
    assert result["failed_count"] == 1
    assert result["highest_risk"] == "high"
    by_id = {item["id"]: item for item in result["items"]}
    assert by_id[1]["threshold_source"] == "default"
    assert by_id[1]["max_risk"] == "medium"
    assert by_id[1]["matched"] is False
    assert by_id[1]["matched_rule_index"] is None
    assert by_id[1]["passed"] is False
    for missing_name_id in (2, 3):
        item = by_id[missing_name_id]
        assert item["threshold_source"] == "default"
        assert item["matched"] is False
        assert item["passed"] is True


def test_gate_records_threshold_boundary_is_inclusive():
    records = [
        _record(1, "a", "high"),
        _record(2, "b", "critical"),
    ]
    result = gate_records(records, rules=[], default_max_risk="high")
    by_id = {item["id"]: item for item in result["items"]}
    assert by_id[1]["passed"] is True   # equal to threshold
    assert by_id[2]["passed"] is False  # above threshold
    assert result["passed"] is False


def test_gate_records_all_pass_overall_passed():
    records = [_record(1, "src/a.py", "high"), _record(2, "x.txt", "info")]
    rules = [("src/**/*.py", "critical"), ("*.txt", "info")]
    result = gate_records(records, rules=rules, default_max_risk="low")
    assert result["passed"] is True
    assert result["result"] == "passed"
    assert result["highest_risk"] == "high"
    assert result["failed_count"] == 0
    by_id = {item["id"]: item for item in result["items"]}
    assert by_id[1]["matched_template"] == "src/**/*.py"
    assert by_id[1]["matched_rule_index"] == 0
    assert by_id[2]["matched_template"] == "*.txt"
    assert by_id[2]["matched_rule_index"] == 1


# ---------------------------------------------------------------------------
# API endpoint
# ---------------------------------------------------------------------------

def _seed_records(client):
    ids = {}
    ids["info_py"] = _post(client, "clean", "src/app.py").json()["id"]
    ids["low_py"] = _post(client, LRE + "x" + PDF, "src/mod.py").json()["id"]
    ids["high_py"] = _post(
        client, "x" + RLO + "evil.exe" + PDF, "src/evil.py"
    ).json()["id"]
    ids["critical_md"] = _post(
        client, RLO + "end.js", "docs/README.md"
    ).json()["id"]
    ids["nameless"] = _post(client, "clean", None).json()["id"]
    return ids


def test_gate_endpoint_full_report(client):
    ids = _seed_records(client)
    resp = _gate(
        client,
        [ids["info_py"], ids["high_py"], ids["critical_md"], ids["nameless"]],
        "medium",
        [
            {"template": "src/**/*.py", "max_risk": "high"},
            {"template": "**/*.md", "max_risk": "low"},
        ],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["default_max_risk"] == "medium"
    assert body["rules"] == [
        {"index": 0, "template": "src/**/*.py", "max_risk": "high"},
        {"index": 1, "template": "**/*.md", "max_risk": "low"},
    ]
    assert body["passed"] is False
    assert body["result"] == "failed"
    assert body["checked"] == 4
    assert body["passed_count"] == 3
    assert body["failed_count"] == 1
    assert body["highest_risk"] == "critical"

    by_id = {item["id"]: item for item in body["items"]}

    info_item = by_id[ids["info_py"]]
    assert info_item["filename"] == "src/app.py"
    assert info_item["actual_risk"] == "info"
    assert info_item["matched_template"] == "src/**/*.py"
    assert info_item["matched_rule_index"] == 0
    assert info_item["threshold_source"] == "rule"
    assert info_item["max_risk"] == "high"
    assert info_item["passed"] is True

    high_item = by_id[ids["high_py"]]
    assert high_item["actual_risk"] == "high"
    assert high_item["max_risk"] == "high"
    assert high_item["passed"] is True

    md_item = by_id[ids["critical_md"]]
    assert md_item["actual_risk"] == "critical"
    assert md_item["matched_template"] == "**/*.md"
    assert md_item["max_risk"] == "low"
    assert md_item["passed"] is False

    nameless = by_id[ids["nameless"]]
    assert nameless["filename"] is None
    assert nameless["matched"] is False
    assert nameless["threshold_source"] == "default"
    assert nameless["max_risk"] == "medium"
    assert nameless["passed"] is True


def test_gate_endpoint_default_when_no_rules(client):
    ids = _seed_records(client)
    resp = _gate(client, [ids["low_py"], ids["high_py"]], "low")
    assert resp.status_code == 200
    body = resp.json()
    assert body["rules"] == []
    by_id = {item["id"]: item for item in body["items"]}
    assert by_id[ids["low_py"]]["passed"] is True
    assert by_id[ids["high_py"]]["passed"] is False
    assert body["passed"] is False


def test_gate_endpoint_specific_rule_beats_general(client):
    ids = _seed_records(client)
    # The generic rule would allow high everywhere; the docs rule must win.
    resp = _gate(
        client,
        [ids["critical_md"]],
        "critical",
        [
            {"template": "**", "max_risk": "critical"},
            {"template": "docs/*.md", "max_risk": "info"},
        ],
    )
    item = resp.json()["items"][0]
    assert item["matched_template"] == "docs/*.md"
    assert item["max_risk"] == "info"
    assert item["passed"] is False


def test_gate_endpoint_response_order_matches_request(client):
    ids = _seed_records(client)
    ordered = [ids["nameless"], ids["critical_md"], ids["info_py"]]
    body = _gate(client, ordered, "critical").json()
    assert [item["id"] for item in body["items"]] == ordered


def test_gate_endpoint_repeated_ids_are_checked_repeatedly(client):
    ids = _seed_records(client)
    body = _gate(client, [ids["info_py"], ids["info_py"]], "info").json()
    assert body["checked"] == 2
    assert [item["id"] for item in body["items"]] == [
        ids["info_py"], ids["info_py"]
    ]


def test_gate_endpoint_missing_id_is_404(client):
    audit_id = _post(client, "clean", "a.txt").json()["id"]
    resp = _gate(client, [audit_id, 9999], "info")
    assert resp.status_code == 404
    assert "9999" in resp.json()["detail"]
    # the first missing ID encountered is reported
    resp2 = _gate(client, [9998, 9999], "info")
    assert resp2.status_code == 404
    assert "9998" in resp2.json()["detail"]


def test_gate_endpoint_is_read_only(client):
    ids = _seed_records(client)
    before = client.get(f"/api/v1/audits/{ids['high_py']}").json()
    _gate(
        client, [ids["high_py"]], "info",
        [{"template": "**", "max_risk": "info"}],
    )
    after = client.get(f"/api/v1/audits/{ids['high_py']}").json()
    assert before == after
    listing = client.get("/api/v1/audits").json()
    assert listing["total"] == len(ids)


def test_gate_endpoint_invalid_bodies_are_422(client):
    assert _gate(client, [], "info").status_code == 422
    assert _gate(client, [1], "bogus").status_code == 422
    assert _gate(client, [0], "info").status_code == 422
    assert _gate(client, ["x"], "info").status_code == 422
    assert _gate(client, [1], None).status_code == 422
    # missing fields
    assert client.post("/api/v1/audits/gate", json={}).status_code == 422
    assert client.post(
        "/api/v1/audits/gate",
        json={"ids": [1], "default_max_risk": "info",
              "rules": [{"template": "", "max_risk": "info"}]},
    ).status_code == 422
    assert client.post(
        "/api/v1/audits/gate",
        json={"ids": [1], "default_max_risk": "info",
              "rules": [{"template": "**", "max_risk": "nope"}]},
    ).status_code == 422
