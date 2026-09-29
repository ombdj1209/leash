"""Upstream tool servers the gateway fronts. Real enough to execute: SQL runs on SQLite, files come
from a virtual filesystem, outbound email and HTTP are captured instead of sent."""
from __future__ import annotations

import posixpath
import sqlite3


class ToolError(Exception):
    pass


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.executescript("""
        CREATE TABLE customers(id INTEGER PRIMARY KEY, name TEXT, email TEXT, iban TEXT, city TEXT);
        CREATE TABLE orders(id INTEGER PRIMARY KEY, customer_id INT, amount_eur REAL, day TEXT);
    """)
    cities = ["Amsterdam", "Utrecht", "Rotterdam", "Eindhoven", "Den Haag"]
    ibans = ["NL91ABNA0417164300", "NL20INGB0001234567", "NL02RABO0123456789", "NL39RABO0300065264", "NL44RABO0123456789"]
    for i in range(1, 51):
        con.execute("INSERT INTO customers VALUES (?,?,?,?,?)",
                    (i, f"Customer {i}", f"customer{i}@mail.example", ibans[i % 5], cities[i % 5]))
    for i in range(1, 401):
        con.execute("INSERT INTO orders VALUES (?,?,?,?)", (i, 1 + i % 50, round(10 + (i * 37) % 190, 2), f"2026-09-{1 + i % 28:02d}"))
    return con


READ_ONLY_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}


def _read_only(action, *_):
    return sqlite3.SQLITE_OK if action in READ_ONLY_ACTIONS else sqlite3.SQLITE_DENY


class Upstream:
    def __init__(self):
        self.db = _db()
        self.files = {
            "/data/public/handbook.md": "Refunds are processed within 5 working days.",
            "/data/public/faq.md": "Delivery slots open 7 days ahead.",
            "/data/secret/keys.txt": "PROD_DB_PASSWORD=hunter2",
        }
        self.docs = ["refund policy: 5 working days", "delivery slots open 7 days ahead",
                     "escalate outages to the on-call channel", "invoices are sent monthly"]
        self.sent_email: list[dict] = []
        self.sent_http: list[dict] = []

    def call(self, name: str, args: dict, read_only_sql: bool = True):
        if name == "sql.query":
            # analytics tool: every query runs inside a savepoint that is rolled back, and (unless the
            # policy says otherwise) under an engine-level authorizer that only permits reads
            self.db.execute("SAVEPOINT q")
            self.db.set_authorizer(_read_only if read_only_sql else None)
            try:
                cur = self.db.execute(args["query"])
                return {"rows": cur.fetchmany(50)}
            except (sqlite3.DatabaseError, sqlite3.Warning) as e:
                raise ToolError(f"sql rejected by engine: {e}") from e
            finally:
                self.db.set_authorizer(None)
                self.db.execute("ROLLBACK TO q")
                self.db.execute("RELEASE q")
        if name == "docs.search":
            q = args.get("q", "").lower()
            return {"hits": [d for d in self.docs if any(w in d for w in q.split())][:5]}
        if name == "files.read":
            p = posixpath.normpath(args["path"])
            if p not in self.files:
                raise ToolError("no such file")
            return {"content": self.files[p]}
        if name == "email.send":
            self.sent_email.append(dict(args))
            return {"status": "queued"}
        if name == "http.post":
            self.sent_http.append(dict(args))
            return {"status": 202}
        if name == "llm.complete":
            return {"text": "ok", "tokens": int(args.get("max_tokens", 256))}
        raise ToolError(f"unknown tool {name}")
