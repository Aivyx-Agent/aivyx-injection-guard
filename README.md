# aivyx-injection-guard

[![CI](https://github.com/Aivyx-Agent/aivyx-injection-guard/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Aivyx-Agent/aivyx-injection-guard/actions/workflows/ci.yml)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)

Heuristic detection of likely prompt-injection markers in untrusted content
that enters an agent's context from outside the user's own direct input.

A case-insensitive phrase-list scan (`scan_for_injection_markers`) against a
fixed, deliberately-non-exhaustive set of known injection phrasings
("ignore previous instructions", "you are now dan", etc.), scanning the
whole input (no size cap), returning a bounded excerpt around any match.
Before matching, the input is normalized: runs of Unicode whitespace (plus
literal `\n`/`\t` escapes, so JSON-serialized content normalizes the same
as its unescaped form) collapse to a single space, and zero-width/format
characters are dropped — so a marker split by a line wrap, an extra space,
or a hidden zero-width character is still caught. The excerpt is always
taken from the original text, with control characters other than `\n`/
`\r`/`\t` stripped. Explicitly a tripwire, not a classifier — the intended
response to a match is "surface it for a human, or an unattended-run
policy, to judge," never a silent classifier verdict. `InjectionTaint` is a
small `Arc<Mutex<Option<...>>>` first-finding-wins shared flag a consumer
can use to persist a match across a session without inventing its own
synchronization; a poisoned mutex is recovered rather than panicking.

No dependencies — pure `std`.

Extracted 2026-09-05 from `aivyx-coder`'s own `aivyx-sandbox` crate
(originally `injection_scan.rs`), which now depends on this crate instead of
maintaining its own copy — same rationale, and the same pattern, as
`aivyx-confine`/`aivyx-checkpoint`/`aivyx-kvcache`.

See `docs/superpowers/specs/2026-09-05-injection-guard-design.md` in the
`aivyx` repo for the full design rationale.
