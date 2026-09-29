# Security Policy

## Supported versions

Only the latest commit on `main` is supported. There are no release branches.

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**. Include:

- what you found and where (file, function, request),
- steps or a minimal payload to reproduce it,
- the impact you expect.

You should get an acknowledgement within 5 working days. Confirmed issues are fixed on `main` with a regression test, and the reporter is credited unless they ask otherwise.

## Scope

Leash is a reference gateway, not a hardened product. The HTTP server has no transport security or caller authentication beyond the `X-Agent-Id` header, budgets and rate limits are in-process, and the audit chain detects tampering but does not prevent it. Run it locally only. Known detection gaps are documented in the README; reports of new bypasses are especially welcome.
