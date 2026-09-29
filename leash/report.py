"""Self-contained HTML report generated from results.json."""
from __future__ import annotations

import html
from pathlib import Path

CSS = """
:root{--ink:#1a1f36;--muted:#5d6480;--line:#e0e3ee;--bg:#fbfbfd;--ok:#1f7a4d;--no:#b3261e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 "Inter","Segoe UI",system-ui,sans-serif}
main{max-width:940px;margin:0 auto;padding:48px 24px 80px}h1{font-size:2rem;line-height:1.15;margin:0 0 8px}
h2{font-size:1.2rem;margin:44px 0 8px}p{max-width:68ch;color:var(--muted)}
table{border-collapse:collapse;width:100%;margin:12px 0;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600}
.n{text-align:right}.wrap{overflow-x:auto}.ok{color:var(--ok);font-weight:600}.no{color:var(--no);font-weight:600}
code{background:#eef0f6;padding:1px 5px;border-radius:3px}
"""


def _t(headers, rows):
    h = "".join(f'<th class="{"n" if i else ""}">{html.escape(x)}</th>' for i, x in enumerate(headers))
    b = "".join("<tr>" + "".join(f'<td class="{"n" if i else ""}">{c}</td>' for i, c in enumerate(r)) + "</tr>" for r in rows)
    return f'<div class="wrap"><table><thead><tr>{h}</tr></thead><tbody>{b}</tbody></table></div>'


def write_report(r: dict, path: Path) -> None:
    f, n = r["full"], r["naive_allowlist_only"]
    cats = sorted(set(f["by_category"]) | set(n["by_category"]))
    rows = [[html.escape(c), f["by_category"][c]["n"], f'{f["by_category"][c]["correct_rate"]:.0%}',
             f'{n["by_category"][c]["correct_rate"]:.0%}'] for c in cats]
    g = r["gate"]
    gate_rows = [[k, f'{v["value"]:.4f}', f'{v["op"]} {v["threshold"]}'] for k, v in g["checks"].items()]
    red = "".join(f"<li><code>{html.escape(s)}</code></li>" for s in r["redaction_samples"])
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Leash results</title><style>{CSS}</style></head><body><main>
<h1>What is this agent allowed to do, right now?</h1>
<p>{f["n_benign"]} benign and {f["n_adversarial"]} adversarial tool calls through the gateway. Runtime {r["environment"]["runtime_s"]} s.
CI gate: <span class="{"ok" if g["passed"] else "no"}">{"passed" if g["passed"] else "failed"}</span>.</p>
<h2>Full policy versus an allow-list alone</h2>
<p>Full: {f["adversarial_block_rate"]:.1%} of adversarial calls stopped, {f["benign_false_block_rate"]:.1%} of benign calls wrongly stopped.
Allow-list only: {n["adversarial_block_rate"]:.1%} stopped.</p>
{_t(["Category", "n", "Correct, full policy", "Correct, allow-list only"], rows)}
<h2>Gate</h2>{_t(["Check", "Value", "Threshold"], gate_rows)}
<h2>Redaction mode</h2><p>The same exfiltration attempts with <code>pii_action = "redact"</code>: what actually left.</p><ul>{red}</ul>
<h2>Mutation fuzzer</h2><p>{r["fuzz"]["blocked"]} of {r["fuzz"]["n"]} rewritten attacks stopped. Misses are listed, not hidden.</p>
{_t(["Variant", "Stopped", "By"], [[html.escape(c["case"]), "yes" if c["blocked"] else "no", html.escape(c["by"])] for c in r["fuzz"]["cases"]])}
<h2>Overhead and integrity</h2>
<p>Policy checks cost {r["overhead_us"]["p50"]:.0f} µs at p50 and {r["overhead_us"]["p99"]:.0f} µs at p99 over {r["overhead_us"]["n"]} calls.
Editing audit entry {r["audit"]["tampered_index"]} of {r["audit"]["entries"]} was detected at entry {r["audit"]["detected_at"]}.</p>
</main></body></html>"""
    Path(path).write_text(doc)
