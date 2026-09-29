"""Runs a suite through a gateway and scores it."""
from __future__ import annotations

from collections import defaultdict

from .gateway import Gateway


def run_cases(gw: Gateway, cases, step_s: float = 2.0):
    rows = []
    for i, c in enumerate(cases):
        gw.clock.offset += step_s
        resp = gw.handle(c.agent, {"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                   "params": {"name": c.tool, "arguments": dict(c.args)}})
        outcome = "allow" if "result" in resp else "block"
        err = resp.get("error", {})
        rows.append({"category": c.category, "expected": c.expected, "outcome": outcome,
                     "code": err.get("message", ""), "detail": str(err.get("data", "")),
                     "check_us": resp.get("meta", {}).get("check_us", 0.0)})
    return rows


def score(rows) -> dict:
    by = defaultdict(lambda: {"n": 0, "correct": 0})
    for r in rows:
        b = by[r["category"]]
        b["n"] += 1
        b["correct"] += r["outcome"] == r["expected"]
    adv = [r for r in rows if r["expected"] == "block"]
    ben = [r for r in rows if r["expected"] == "allow"]
    return {
        "adversarial_block_rate": sum(r["outcome"] == "block" for r in adv) / max(1, len(adv)),
        "benign_false_block_rate": sum(r["outcome"] == "block" for r in ben) / max(1, len(ben)),
        "n_adversarial": len(adv), "n_benign": len(ben),
        "by_category": {k: {"n": v["n"], "correct_rate": v["correct"] / v["n"]} for k, v in sorted(by.items())},
    }
