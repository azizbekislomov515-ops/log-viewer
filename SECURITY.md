# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a vulnerability

Please report security problems privately, through the repository's private
vulnerability reporting ("Report a vulnerability" on the Security tab), not as a public
issue. Include the LogLens version, your distribution, and the smallest input that shows
the problem. That can be a log line, a rule pack or a helper request.

You will get an answer within a week. Fixes are released as soon as they are ready and
credited in the changelog unless you prefer otherwise.

## Scope

LogLens treats **log content, container labels and rule packs from outside the built-in
set as hostile**. In scope, for example:

- a log line that makes LogLens run code, hang, crash, or drive the terminal
- a secret that survives redaction into the database, an export or a report
- reading logs through `loglens-helper` that its configuration does not allow
- a rule pack that escapes the template sandbox

How LogLens defends against these, and the limitations it accepts, are in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). Hardening and privilege setup are in
[docs/SECURITY.md](docs/SECURITY.md).
