"""PII detectors with checksums where the format has one, applied after Unicode normalisation so
zero-width characters and full-width digits cannot smuggle data past a regex."""
from __future__ import annotations

import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}\b")
CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
PHONE = re.compile(r"(?:\+|00)\d{1,3}[\s-]?\d(?:[\s-]?\d){7,11}\b|\b06[\s-]?\d{8}\b")
BSN = re.compile(r"\b\d{9}\b")


def normalise(text: str) -> str:
    return unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)


def _iban_ok(s: str) -> bool:
    s = s.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    r = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in r)) % 97 == 1


def _luhn_ok(s: str) -> bool:
    d = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, x in enumerate(reversed(d)):
        if i % 2:
            x *= 2
            x -= 9 if x > 9 else 0
        total += x
    return total % 10 == 0


def _bsn_ok(s: str) -> bool:  # Dutch citizen service number, 11-proof
    d = [int(c) for c in s]
    return (sum(w * x for w, x in zip(range(9, 1, -1), d[:8])) - d[8]) % 11 == 0 and d[0] != 0


def find(text: str, allow_email_domains=()) -> list[tuple[str, str]]:
    t = normalise(text)
    hits = []
    for m in EMAIL.finditer(t):
        if m.group(0).split("@", 1)[1].lower() not in allow_email_domains:
            hits.append(("email", m.group(0)))
    hits += [("iban", m.group(0)) for m in IBAN.finditer(t) if _iban_ok(m.group(0))]
    compact = re.sub(r"(?<=[A-Za-z0-9])[.\-](?=[A-Za-z0-9])", "", t).upper()   # NL91-ABNA-..., lowercase IBANs
    hits += [("iban", m.group(0)) for m in IBAN.finditer(compact) if _iban_ok(m.group(0))
             and ("iban", m.group(0)) not in hits]
    hits += [("card", m.group(0)) for m in CARD.finditer(t) if _luhn_ok(m.group(0))]
    hits += [("phone", m.group(0)) for m in PHONE.finditer(t)]
    hits += [("bsn", m.group(0)) for m in BSN.finditer(t) if _bsn_ok(m.group(0))]
    return hits


def redact(text: str, hits) -> str:
    t = normalise(text)
    for kind, value in sorted(hits, key=lambda h: -len(h[1])):
        t = t.replace(value, f"[{kind.upper()}]")
    return t
