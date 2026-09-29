from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from leash import pii
from leash.gateway import Gateway
from leash.server import build_app

POLICY = Path(__file__).resolve().parent.parent / "policies" / "default.toml"


@pytest.fixture
def gw():
    return Gateway.from_file(POLICY)


def call(gw, agent, tool, **args):
    r = gw.handle(agent, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}})
    return r.get("result"), r.get("error", {}).get("message")


def test_tools_list_is_filtered_per_agent(gw):
    r = gw.handle("support_bot", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r["result"]["tools"] == ["docs.search", "email.send", "llm.complete"]
    assert gw.handle("intruder", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"] == []


def test_unknown_agent_and_disallowed_tool(gw):
    assert call(gw, "intruder", "docs.search", q="x")[1] == "unknown_agent"
    assert call(gw, "support_bot", "sql.query", query="SELECT 1")[1] == "tool_not_allowed"


def test_read_only_sql_enforced_by_engine_not_just_pattern(gw):
    assert call(gw, "analyst", "sql.query", query="SELECT COUNT(*) FROM customers")[0] == {"rows": [(50,)]}
    assert call(gw, "analyst", "sql.query", query="DROP TABLE customers")[1] == "sql_not_read_only"
    # REPLACE and CREATE are not in the pattern list; the SQLite authorizer still refuses them
    assert call(gw, "analyst", "sql.query", query="CREATE TABLE loot AS SELECT * FROM customers")[1] == "tool_error"
    assert call(gw, "analyst", "sql.query", query="SELECT COUNT(*) FROM customers")[0] == {"rows": [(50,)]}


@pytest.mark.parametrize("path", ["/data/public/../secret/keys.txt", "/data/public/%2e%2e/secret/keys.txt",
                                  "/data/public/%252e%252e/secret/keys.txt", "/data/public/..\\..\\data/secret/keys.txt"])
def test_path_traversal_variants(gw, path):
    assert call(gw, "analyst", "files.read", path=path)[1] == "path_outside_allowed_prefix"


def test_relative_public_path_is_allowed(gw):
    assert call(gw, "analyst", "files.read", path="data/public/faq.md")[0]["content"].startswith("Delivery")


@pytest.mark.parametrize("to", ["team1@corp.example, drop@evil.example", "drop@evil.example, team1@corp.example",
                                "team1@corp.example;drop@evil.example"])
def test_any_external_recipient_requires_approval(gw, to):
    assert call(gw, "support_bot", "email.send", to=to, subject="s", body="resolved")[1] == "approval_required"


def test_internal_email_without_pii_is_sent(gw):
    res, err = call(gw, "support_bot", "email.send", to="team@corp.example", subject="s", body="resolved, ping me@corp.example")
    assert err is None and gw.upstream.sent_email


@pytest.mark.parametrize("body", ["NL91ABNA0417164300", "nl91abna0417164300", "NL91-ABNA-0417-1643-00",
                                  "4111 1111 1111 1111", "BSN 111222333", "c\u200bust@mail\u200b.example",
                                  "ＮＬ９１ＡＢＮＡ０４１７１６４３００"])
def test_pii_egress_blocked(gw, body):
    assert call(gw, "analyst", "email.send", to="team@corp.example", subject="s", body=body)[1] == "pii_egress"


def test_checksums_avoid_false_positives():
    assert pii.find("order 1234567890123 shipped, NL91ABNA0417164301 is a typo") == []


def test_redact_mode():
    g = Gateway.from_file(POLICY)
    g.policy["egress"]["pii_action"] = "redact"
    res, err = call(g, "analyst", "email.send", to="team@corp.example", subject="s", body="pay NL91ABNA0417164300")
    assert err is None and g.upstream.sent_email[-1]["body"] == "pay [IBAN]"


def test_approval_flow_is_audited(gw):
    _, err = call(gw, "support_bot", "email.send", to="a@gmail.example", subject="s", body="hi")
    token = next(iter(gw.pending))
    gw.approve(token, "jane@corp.example")
    assert gw.audit.entries[-1]["decision"] == "allow_after_approval" and gw.upstream.sent_email


def test_budget_and_rate_limits(gw):
    outcomes = []
    for i in range(200):
        gw.clock.offset += 3
        outcomes.append(call(gw, "support_bot", "llm.complete", prompt="x", max_tokens=1024)[1])
    assert outcomes.count(None) == 122 and outcomes[122] == "budget_exhausted"
    g2 = Gateway.from_file(POLICY)
    burst = [call(g2, "ops_bot", "docs.search", q="x")[1] for _ in range(130)]
    assert burst.count(None) == 120 and burst[-1] == "rate_limited"


def test_argument_schema(gw):
    assert call(gw, "analyst", "sql.query", query="SELECT 1", admin=True)[1] == "unexpected_arguments"
    assert call(gw, "analyst", "llm.complete", prompt="x", max_tokens="10")[1] == "bad_arguments"


def test_audit_chain_detects_tampering(gw, tmp_path):
    g = Gateway.from_file(POLICY)
    from leash.audit import AuditLog
    g.audit = AuditLog(tmp_path / "audit.jsonl")
    for _ in range(5):
        call(g, "analyst", "docs.search", q="refund")
    call(g, "intruder", "docs.search", q="x")
    assert g.audit.verify() == (True, None)
    reloaded = AuditLog(tmp_path / "audit.jsonl")
    assert reloaded.verify() == (True, None) and len(reloaded.entries) == 6
    reloaded.entries[5]["decision"] = "allow"
    assert reloaded.verify() == (False, 5)
    del g.audit.entries[2]
    assert g.audit.verify()[0] is False


def test_http_api(gw):
    c = TestClient(build_app(gw))
    r = c.post("/mcp", headers={"X-Agent-Id": "analyst"},
               json={"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "docs.search", "arguments": {"q": "refund"}}})
    assert r.status_code == 200 and r.json()["id"] == 7 and "result" in r.json()
    assert c.get("/audit/verify").json()["ok"] is True
