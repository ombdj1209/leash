"""Reproduces every number in the README and acts as the CI gate.

    python run_eval.py           # evaluate, write results/, exit 1 if the gate fails
"""
from __future__ import annotations

import json
import platform
import sys
import time
import tomllib
from pathlib import Path

import numpy as np

from leash.evalsuite import budget_burn, suite
from leash.fuzz import variants as fuzz_variants
from leash.gateway import Gateway
from leash.report import write_report
from leash.runner import run_cases, score

ROOT = Path(__file__).resolve().parent
POLICY = ROOT / "policies" / "default.toml"
OUT = ROOT / "results"


def main() -> int:
    t0 = time.time()
    cases = suite(seed=0, n_benign=600)
    pol = tomllib.loads(POLICY.read_text())

    full_gw = Gateway.from_file(POLICY)
    full_rows = run_cases(full_gw, cases)
    naive_rows = run_cases(Gateway.from_file(POLICY, naive=True), cases)
    full, naive = score(full_rows), score(naive_rows)

    # which layer stopped destructive SQL: the pattern, or the engine-level read-only authorizer
    sql = [r for r in full_rows if r["category"] == "sql/destructive"]
    sql_layers = {"pattern": sum(r["code"] == "sql_not_read_only" for r in sql),
                  "engine": sum(r["code"] == "tool_error" for r in sql),
                  "missed": sum(r["outcome"] == "allow" for r in sql), "n": len(sql)}

    # looping agent against the daily budget
    burn = budget_burn(pol["agents"]["support_bot"]["daily_budget_eur"], pol["pricing"]["llm.complete"])
    burn_rows = run_cases(Gateway.from_file(POLICY), burn, step_s=3.0)
    burn_score = score(burn_rows)
    allowed = sum(r["outcome"] == "allow" for r in burn_rows)
    first_block = next((r["code"] for r in burn_rows if r["outcome"] == "block"), None)

    # burst against the rate limit
    gw = Gateway.from_file(POLICY)
    burst = [gw.handle("ops_bot", {"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                   "params": {"name": "docs.search", "arguments": {"q": "outages"}}}) for i in range(200)]
    burst_allowed = sum("result" in b for b in burst)

    # redact mode: same exfiltration attempts, PII replaced instead of blocked
    red_pol = json.loads(json.dumps(pol))
    red_pol["egress"]["pii_action"] = "redact"
    red_gw = Gateway(red_pol)
    run_cases(red_gw, [c for c in cases if c.category == "exfil/pii_internal"])
    redacted_samples = [e["body"] for e in red_gw.upstream.sent_email][:4]

    # policy-check overhead (checks only, upstream excluded), on benign traffic
    bench_gw = Gateway.from_file(POLICY)
    bench_gw.policy["agents"]["analyst"]["rate_per_min"] = 10 ** 9
    bench_gw.policy["agents"]["analyst"]["daily_budget_eur"] = 10 ** 9
    bench_cases = [c for c in suite(seed=1, n_benign=3000) if c.expected == "allow" and c.agent == "analyst"]
    bench_rows = run_cases(bench_gw, bench_cases, step_s=0.0)
    us = np.array([r["check_us"] for r in bench_rows])

    # tamper evidence
    ok_before, _ = full_gw.audit.verify()
    k = next(i for i, e in enumerate(full_gw.audit.entries) if e["decision"] == "deny")
    full_gw.audit.entries[k]["decision"] = "allow"          # an attacker rewrites a denial as an approval
    ok_after, bad_at = full_gw.audit.verify()

    # mutation fuzzer: reported, not gated, so remaining gaps stay visible
    fz_rows = run_cases(Gateway.from_file(POLICY), fuzz_variants())
    fuzz = {"n": len(fz_rows), "blocked": sum(r["outcome"] == "block" for r in fz_rows),
            "cases": [{"case": r["category"], "blocked": r["outcome"] == "block", "by": r["code"] or "not blocked"}
                      for r in fz_rows]}

    gate = tomllib.loads((ROOT / "policies" / "gate.toml").read_text())
    p99_ms = float(np.percentile(us, 99)) / 1000
    checks = {
        "adversarial_block_rate": (full["adversarial_block_rate"], ">=", gate["min_adversarial_block_rate"]),
        "benign_false_block_rate": (full["benign_false_block_rate"], "<=", gate["max_benign_false_block_rate"]),
        "p99_overhead_ms": (p99_ms, "<=", gate["max_p99_overhead_ms"]),
    }
    passed = all((v >= t) if op == ">=" else (v <= t) for v, op, t in checks.values())

    results = {
        "environment": {"python": platform.python_version(), "machine": platform.machine(),
                        "runtime_s": round(time.time() - t0, 1)},
        "full": full, "naive_allowlist_only": naive, "sql_layers": sql_layers,
        "budget": {"calls": len(burn), "allowed": allowed, "expected_allowed": sum(c.expected == "allow" for c in burn),
                   "correct_rate": burn_score["by_category"]["budget/loop"]["correct_rate"], "first_block_code": first_block},
        "rate_burst": {"calls": 200, "allowed": burst_allowed,
                       "limit_per_min": pol["agents"]["ops_bot"]["rate_per_min"]},
        "redaction_samples": redacted_samples,
        "overhead_us": {"n": int(len(us)), "p50": float(np.percentile(us, 50)), "p99": float(np.percentile(us, 99)),
                        "max": float(us.max())},
        "audit": {"entries": len(full_gw.audit.entries), "verifies_before_tamper": ok_before,
                  "verifies_after_tamper": ok_after, "tampered_index": k, "detected_at": bad_at},
        "fuzz": fuzz,
        "gate": {"passed": passed, "checks": {k_: {"value": v, "op": op, "threshold": t} for k_, (v, op, t) in checks.items()}},
    }
    OUT.mkdir(exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(results, indent=2))
    write_report(results, OUT / "report.html")
    print(f"full:  block {full['adversarial_block_rate']:.1%} of {full['n_adversarial']} adversarial, "
          f"false-block {full['benign_false_block_rate']:.1%} of {full['n_benign']} benign")
    print(f"naive: block {naive['adversarial_block_rate']:.1%}, false-block {naive['benign_false_block_rate']:.1%}")
    print(f"sql layers {sql_layers}; budget allowed {allowed}/{len(burn)}; burst allowed {burst_allowed}/200")
    print(f"overhead p50 {results['overhead_us']['p50']:.0f} us p99 {results['overhead_us']['p99']:.0f} us; "
          f"audit tamper detected at {bad_at} (tampered {k})")
    for name, (v, op, t) in checks.items():
        print(f"gate {name}: {v:.4f} {op} {t} -> {'ok' if ((v >= t) if op == '>=' else (v <= t)) else 'FAIL'}")
    for cat, v in full["by_category"].items():
        if v["correct_rate"] < 1:
            print("  imperfect:", cat, v)
    print(f"fuzz: {fuzz['blocked']}/{fuzz['n']} blocked")
    for c in fuzz["cases"]:
        print(f"  {'ok  ' if c['blocked'] else 'MISS'} {c['case']:40s} {c['by']}")
    print("GATE", "PASSED" if passed else "FAILED")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
