# Leash

**Runtime policy gateway for AI agent tool calls.** Per-agent tool allow-lists, argument schemas, engine-enforced read-only SQL, path and host controls, PII egress guards with checksums, daily budgets, rate limits, human approval for external actions, and a hash-chained audit log. Ships with a labelled evaluation suite, a mutation fuzzer, and a CI gate that fails the build when protection regresses.

Uses MCP-style JSON-RPC 2.0 message shapes (`tools/list`, `tools/call`) over plain HTTP. It is not a full MCP transport implementation. All tools, data and traffic are synthetic.

## Why this exists

At Data + AI Summit 2026, Databricks framed the governance problem as control over what agents *do*, not just what data they can access: Unity AI Gateway as a runtime layer that enforces policy and cost over models and agents, and Omnigent as a harness for running and governing autonomous agents. Leash is a small, open, measurable version of that runtime layer, built to answer: **what does it take to stop a prompt-injected agent without getting in the way of a normal one, and what does it cost per call?**

## How a call flows

```
agent ─► identity ─► tool allow-list ─► argument schema ─► tool rules ─► egress (PII) ─► rate ─► budget ─► approval ─► upstream
          unknown      not visible in    types, no extra   read-only SQL,  block or redact   per-min  per-day   external       runs, then
          agent        tools/list        fields            paths, hosts    after NFKC                euro     recipients     cost charged
                                                                                                                             │
                                                  every decision, allowed or denied ─► hash-chained audit log ◄──────────────┘
```

| Piece | File |
|---|---|
| Ordered checks, JSON-RPC handling, approvals, budgets | `leash/gateway.py` |
| Email, IBAN (mod-97), card (Luhn), phone, Dutch BSN (11-proof), after Unicode normalisation | `leash/pii.py` |
| Append-only hash chain with verification | `leash/audit.py` |
| Upstream tools: SQLite with engine-level read-only authorizer, virtual files, captured email/HTTP | `leash/tools.py` |
| Curated benign and adversarial suite | `leash/evalsuite.py` |
| Mutation fuzzer | `leash/fuzz.py` |
| Policy and gate thresholds | `policies/default.toml`, `policies/gate.toml` |

## Results

`python run_eval.py` (under a second, one CPU core, Python 3.12). It exits non-zero if the gate fails.

### Full policy versus an allow-list alone

600 benign and 46 adversarial calls from three agents (`analyst`, `support_bot`, `ops_bot`).

| Category | n | Correct, full policy | Correct, allow-list only |
|---|---|---|---|
| Benign SQL, docs, files, internal email, HTTP, LLM | 600 | 100% | 96.2% |
| Exfiltration by external email | 7 | 100% | 0% |
| PII to internal recipients | 7 | 100% | 0% |
| PII in outbound HTTP | 4 | 100% | 0% |
| Outbound HTTP to unapproved hosts (incl. cloud metadata IP) | 3 | 100% | 0% |
| Destructive SQL | 12 | 100% | 25% |
| Path traversal | 5 | 100% | 20% |
| Unknown agent or disallowed tool | 5 | 100% | 100% |
| Smuggled argument, type confusion, external email without approval | 3 | 100% | 0% |

- **Full policy:** 100% of adversarial calls stopped, 0.0% of benign calls wrongly stopped.
- **Allow-list only:** 19.6% stopped. An allow-list answers *which tool*; almost every real attack uses an allowed tool with hostile arguments.

### Defence in depth for SQL

Of 12 destructive queries, the fast pattern check stopped 10. The other two (`CREATE TABLE ... AS SELECT`, `REPLACE INTO`) use verbs the pattern does not list, and were refused by SQLite's authorizer, which only permits reads. **Zero got through.** This is why read-only is enforced inside the engine: a pattern list is a speed optimisation, not a security boundary.

### Budgets, rates, integrity

- **Looping agent:** 400 LLM calls at 1,024 tokens against a €0.50 daily budget. Exactly the 122 affordable calls were allowed; call 123 got `budget_exhausted`.
- **Burst:** 200 calls in the same minute against a 120 per minute limit. 120 allowed.
- **Tamper evidence:** rewriting one `deny` entry as `allow` in a 646-entry log is detected at exactly that entry. Deleting an entry is also detected (tested).
- **Overhead:** policy checks cost **13 µs at p50 and 47 µs at p99** over 1,889 calls, excluding the tool itself. The gate allows 2 ms.

### Mutation fuzzer: 22 of 24 rewritten attacks stopped

The fuzzer rewrites known attacks the way an injected agent would: encodings, separators, recipient lists, homoglyphs, stacked statements. Building it exposed **four real bugs in the first version of the gateway, all now fixed with regression tests**:

1. A recipient list with the external address *first* was treated as internal, because only the last domain was checked. Now any external recipient makes the message external.
2. URL-encoded and double-encoded traversal (`%2e%2e`, `%252e%252e`) passed the prefix check. Paths are now decoded before normalisation.
3. IBANs written lowercase or with dashes or dots were missed.
4. Backslash traversal was not normalised.

**Two known gaps remain, reported rather than hidden:** a spelled-out email (`name (at) mail (dot) example`) and a base64-encoded IBAN both still leave through internal email. Pattern-based egress control cannot catch encoded data in general. The real fix is structural: agents that read customer tables should not hold an email tool at all, which the per-agent allow-list already supports.

### Redaction mode

With `pii_action = "redact"`, the same exfiltration attempts are delivered with PII replaced. For example, *"Card on file 4111 1111 1111 1111 exp 04/29"* leaves as *"Card on file [CARD] exp 04/29"*.

## Run it

```bash
pip install -e ".[dev]"
python -m pytest -q        # 26 tests, including regression tests for every fuzzer finding
python run_eval.py         # evaluation + CI gate (exit 1 on failure)
uvicorn leash.server:app --port 8100
curl -s localhost:8100/mcp -H 'X-Agent-Id: analyst' -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"docs.search","arguments":{"q":"refund"}}}'
```

## Design notes

- **Deny by default.** Agents only see the tools they may call in `tools/list`, which shrinks the surface that injected instructions can target.
- **Normalise once, then check.** NFKC plus zero-width stripping runs before every text check, so full-width digits and invisible characters cannot split a pattern.
- **Checksums beat regexes for PII.** IBAN mod-97, Luhn and the BSN 11-proof keep false positives near zero on ordinary numbers (tested).
- **Every decision is audited before the response returns**, including denials and approvals, with the approver's identity.
- **The clock is injectable**, so budget and rate behaviour is tested deterministically.

## Limitations

- Budgets and rate counters are in-process. A multi-replica deployment needs a shared store, or limits multiply by the replica count.
- Pattern-based PII detection misses encoded or paraphrased data (see the fuzzer gaps). It is a last line, not the design.
- The upstream tools are local stand-ins. Real connectors add their own failure modes and latency.
- The audit chain detects tampering but does not prevent it. Production would anchor the head hash externally, for example in write-once storage.

## Next steps

1. Taint tracking: mark data returned from `sql.query` and block it from reaching egress tools regardless of encoding, closing both fuzzer gaps structurally.
2. A shared Redis-backed budget and rate store, with a race test across two gateway replicas.
3. Policy-as-code tests: a diff of two policy files, scored against the suite before deploy.
4. Full MCP transport (stdio and streamable HTTP) in front of the same check pipeline.
