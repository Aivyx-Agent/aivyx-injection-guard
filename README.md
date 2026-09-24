# aivyx-injection-guard

[![CI](https://github.com/Aivyx-Agent/aivyx-injection-guard/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Aivyx-Agent/aivyx-injection-guard/actions/workflows/ci.yml)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)

Heuristic detection of likely prompt-injection markers in untrusted content
that enters an agent's context from outside the user's own direct input.

A case-insensitive phrase-list scan (`scan_for_injection_markers`) against a
fixed, deliberately-non-exhaustive set of known injection phrasings
("ignore previous instructions", "you are now", etc.), bounded to a 64KB
scan window, returning a bounded excerpt around any match. Explicitly a
tripwire, not a classifier — the intended response to a match is "surface it
for a human, or an unattended-run policy, to judge," never a silent
classifier verdict. `InjectionTaint` is a small `Arc<Mutex<Option<...>>>`
first-finding-wins shared flag a consumer can use to persist a match across
a session without inventing its own synchronization.

No dependencies — pure `std`.

Extracted 2026-09-05 from `aivyx-coder`'s own `aivyx-sandbox` crate
(originally `injection_scan.rs`), which now depends on this crate instead of
maintaining its own copy — same rationale, and the same pattern, as
`aivyx-confine`/`aivyx-checkpoint`/`aivyx-kvcache`.

See `docs/superpowers/specs/2026-09-05-injection-guard-design.md` in the
`aivyx` repo for the full design rationale.
