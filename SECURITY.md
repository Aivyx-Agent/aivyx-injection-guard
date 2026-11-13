# Security Policy

aivyx-injection-guard flags text that tries to take over an agent
(prompt injection) in web pages, files and tool output. It is a
heuristic tripwire, not a guarantee, so a phrase it misses is expected;
a way to crash it, make it hang, or hide a known phrase from it (for
example with invisible characters it should normalise) is in scope.

This is not a bug bounty program.

## Reporting a vulnerability

Report it privately on GitHub: [Report a vulnerability](https://github.com/Aivyx-Agent/aivyx-injection-guard/security/advisories/new)
(this repo's **Security** tab). Only the maintainer sees the report
until a fix is published. Please don't open a public issue for a
vulnerability.

We aim to resolve or provide a remediation plan for a confirmed
vulnerability within 90 days of the report, or coordinate a later
disclosure date with the reporter if a fix genuinely needs longer.
Credit is offered in release notes at the reporter's preference.
