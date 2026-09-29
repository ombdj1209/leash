"""HTTP front door.  uvicorn leash.server:app --port 8100

POST /mcp            JSON-RPC body, agent identity in the X-Agent-Id header
POST /approve/{tok}  a human approves a held call
GET  /audit/verify   recompute the hash chain
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException

from .gateway import Gateway

POLICY = Path(os.environ.get("LEASH_POLICY", Path(__file__).resolve().parent.parent / "policies" / "default.toml"))


def build_app(gw: Gateway) -> FastAPI:
    app = FastAPI(title="Leash", version="0.1.0")

    @app.post("/mcp")
    def mcp(req: dict, x_agent_id: str = Header(...)):
        return gw.handle(x_agent_id, req)

    @app.post("/approve/{token}")
    def approve(token: str, x_approver: str = Header(...)):
        if token not in gw.pending:
            raise HTTPException(404, "no such pending call")
        return gw.approve(token, x_approver)

    @app.get("/audit/verify")
    def verify():
        ok, bad = gw.audit.verify()
        return {"ok": ok, "first_bad_entry": bad, "entries": len(gw.audit.entries)}

    return app


app = build_app(Gateway.from_file(POLICY))
