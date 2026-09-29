"""The gateway. Every tool call passes the same ordered checks, and every decision, allowed or not,
is written to the hash-chained audit log before the response leaves.

Order matters: cheap identity and allow-list checks run first, argument checks next, egress (PII)
next, then rate and budget, then human approval. The upstream is only called when all pass.
Speaks MCP-style JSON-RPC 2.0 message shapes (tools/list, tools/call); transport is plain HTTP here.
"""
from __future__ import annotations

import posixpath
import re
import time
import tomllib
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlparse

from . import pii
from .audit import AuditLog
from .tools import ToolError, Upstream

DENY_SQL = re.compile(r"(?i)\b(drop|delete|truncate|alter|grant|insert|update|attach|pragma)\b")
TOOL_SCHEMAS = {
    "sql.query": {"query": str}, "docs.search": {"q": str}, "files.read": {"path": str},
    "email.send": {"to": str, "subject": str, "body": str}, "http.post": {"url": str, "body": str},
    "llm.complete": {"prompt": str, "max_tokens": int},
}


class Denied(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code, self.detail = code, detail


@dataclass
class Clock:
    """Injectable clock so budgets and rate limits are testable."""
    offset: float = 0.0

    def now(self) -> float:
        return time.time() + self.offset


@dataclass
class Gateway:
    policy: dict
    upstream: Upstream = field(default_factory=Upstream)
    audit: AuditLog = field(default_factory=AuditLog)
    clock: Clock = field(default_factory=Clock)
    naive: bool = False                  # ablation: allow-list only, no argument/egress/budget checks
    spend: dict = field(default_factory=lambda: defaultdict(float))
    calls: dict = field(default_factory=lambda: defaultdict(deque))
    pending: dict = field(default_factory=dict)

    @classmethod
    def from_file(cls, path, **kw):
        return cls(tomllib.loads(Path(path).read_text()), **kw)

    # ---------------------------------------------------------------- JSON-RPC
    def handle(self, agent: str, req: dict) -> dict:
        rid, method, params = req.get("id"), req.get("method"), req.get("params") or {}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": rid, "result": {"tools": self.visible_tools(agent)}}
        if method != "tools/call":
            return self._err(rid, -32601, "method_not_found")
        t0 = time.perf_counter()
        name, args = params.get("name", ""), dict(params.get("arguments") or {})
        entry = {"t": round(self.clock.now(), 3), "agent": agent, "tool": name, "args": args}
        try:
            args = self.check(agent, name, args)
            check_us = (time.perf_counter() - t0) * 1e6
            result = self.upstream.call(name, args, read_only_sql=self._arg_rules(agent, name).get("read_only", True)
                                        if not self.naive else False)
            self._charge(agent, name, args, result)
            self.audit.append({**entry, "decision": "allow", "check_us": round(check_us, 1)})
            return {"jsonrpc": "2.0", "id": rid, "result": result, "meta": {"check_us": check_us}}
        except Denied as d:
            check_us = (time.perf_counter() - t0) * 1e6
            self.audit.append({**entry, "decision": "deny", "code": d.code, "detail": d.detail})
            return {**self._err(rid, -32001, d.code, d.detail), "meta": {"check_us": check_us}}
        except ToolError as e:
            self.audit.append({**entry, "decision": "tool_error", "detail": str(e)})
            return self._err(rid, -32002, "tool_error", str(e))

    @staticmethod
    def _err(rid, code, message, detail=""):
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message, "data": detail}}

    def visible_tools(self, agent: str) -> list[str]:
        """Agents only see what they may call: a smaller surface for injected instructions to aim at."""
        a = self.policy.get("agents", {}).get(agent)
        return sorted(a["allowed_tools"]) if a else []

    def _arg_rules(self, agent, name) -> dict:
        return self.policy["agents"][agent].get("args", {}).get(name, {})

    # ------------------------------------------------------------------ checks
    def check(self, agent: str, name: str, args: dict) -> dict:
        a = self.policy.get("agents", {}).get(agent)
        if a is None:
            raise Denied("unknown_agent")
        if name not in a["allowed_tools"]:
            raise Denied("tool_not_allowed", name)
        if self.naive:
            return args
        schema = TOOL_SCHEMAS.get(name, {})
        for k, typ in schema.items():
            if k not in args or not isinstance(args[k], typ):
                raise Denied("bad_arguments", f"{k} must be {typ.__name__}")
        if set(args) - set(schema):
            raise Denied("unexpected_arguments", ",".join(sorted(set(args) - set(schema))))
        rules = self._arg_rules(agent, name)
        if name == "sql.query":
            q = pii.normalise(args["query"])
            if len(q) > rules.get("max_len", 4000):
                raise Denied("query_too_long")
            if DENY_SQL.search(q):
                raise Denied("sql_not_read_only", "blocked by pattern")
            args["query"] = q
        if name == "files.read":
            raw = pii.normalise(args["path"]).replace("\\", "/")
            for _ in range(3):                                   # undo (double) URL encoding before checking
                raw = unquote(raw)
            p = posixpath.normpath("/" + raw.lstrip("/"))
            if not p.startswith(rules.get("path_prefix", "/nonexistent/")):
                raise Denied("path_outside_allowed_prefix", p)
            args["path"] = p
        eg = self.policy.get("egress", {})
        external = False
        if name == "email.send":
            # every address in the field counts: one external recipient makes the whole message external
            doms = [a.rsplit("@", 1)[1].lower() for a in pii.EMAIL.findall(pii.normalise(args["to"]))]
            if not doms:
                raise Denied("bad_recipient")
            external = any(d not in eg.get("internal_email_domains", []) for d in doms)
        if name == "http.post":
            host = urlparse(pii.normalise(args["url"])).hostname or ""
            if host not in eg.get("allowed_http_hosts", []):
                raise Denied("http_host_not_allowed", host)
            external = True
        if name in eg.get("external_tools", []):
            text = " ".join(str(v) for k, v in args.items() if k != "to")
            hits = pii.find(text, eg.get("internal_email_domains", []))
            if hits:
                if eg.get("pii_action", "block") == "redact":
                    for k in list(args):
                        if k != "to" and isinstance(args[k], str):
                            args[k] = pii.redact(args[k], hits)
                else:
                    raise Denied("pii_egress", ",".join(sorted({h[0] for h in hits})))
        self._rate(agent, a)
        est = self._price(name, args)
        if self.spend[(agent, self._day())] + est > a["daily_budget_eur"]:
            raise Denied("budget_exhausted", f"{self.spend[(agent, self._day())]:.3f} of {a['daily_budget_eur']}")
        if f"{name}:external" in a.get("require_approval", []) and external:
            token = uuid.uuid4().hex[:12]
            self.pending[token] = (agent, name, dict(args))
            raise Denied("approval_required", token)
        return args

    def _day(self) -> int:
        return int(self.clock.now() // 86400)

    def _rate(self, agent, a):
        q, now = self.calls[agent], self.clock.now()
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= a.get("rate_per_min", 60):
            raise Denied("rate_limited")
        q.append(now)

    def _price(self, name, args) -> float:
        p = self.policy.get("pricing", {}).get(name, 0.0)
        return p * args.get("max_tokens", 1000) / 1000 if name == "llm.complete" else p

    def _charge(self, agent, name, args, result):
        if not self.naive:
            self.spend[(agent, self._day())] += self._price(name, args)

    def approve(self, token: str, approver: str) -> dict:
        agent, name, args = self.pending.pop(token)
        result = self.upstream.call(name, args)
        self._charge(agent, name, args, result)
        self.audit.append({"t": round(self.clock.now(), 3), "agent": agent, "tool": name, "args": args,
                           "decision": "allow_after_approval", "approver": approver})
        return result
