# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## What this is

`aivyx-injection-guard` is a small, dependency-free prompt-injection
phrase-list tripwire: `scan_for_injection_markers(text, source)` plus a
shared `InjectionTaint` flag. It exists so `aivyx-coder` and `aivyx` (the
flagship Personal Assistant) can share one implementation of the same
detection primitive, rather than each maintaining — and potentially
drifting on — its own copy. See `README.md` and `aivyx/docs/superpowers/
specs/2026-09-05-injection-guard-design.md` for the full rationale — this
file only covers what's specific to working in this repo's code.

## Build, test, lint

```sh
cargo build
cargo test
cargo clippy --all-targets
cargo fmt
```

Single crate, no workspace — no `-p` flag needed. Single test:
`cargo test <test_name>`.

## Architecture

Everything lives in `src/lib.rs` — there's no submodule split (unlike
`aivyx-confine`'s trait-vs-backend split), since this crate has no
alternate-backend concept: one scan function, one marker list, one shared
taint type.

- `INJECTION_MARKERS` — the fixed, deliberately-non-exhaustive phrase list.
  Every entry must be lowercase ASCII (the scan lowercases with
  `to_ascii_lowercase()`, not `to_lowercase()`, to keep byte offsets stable
  across full Unicode case-folding edge cases — see
  `scan_keeps_correct_byte_offsets_when_lowercasing_changes_length`'s test
  for why that distinction matters).
- `scan_for_injection_markers` — case-insensitive substring match within a
  bounded `SCAN_WINDOW_BYTES` (64KB) window, returning the first match by
  position *in the marker list*, not by position in the text.
- `InjectionFinding` — what tripped it (`matched_pattern`), where from
  (`source`, a caller-supplied human-readable label), and a bounded excerpt
  for a human to judge at a glance.
- `InjectionTaint` — an `Arc<Mutex<Option<InjectionFinding>>>` wrapper,
  first-finding-wins. Not required to use this crate's detection — a
  consumer can call `scan_for_injection_markers` directly and build its own
  response, the way `aivyx` does (converting a match directly into an
  existing turn-outcome type rather than persisting a taint flag).

## Where to look next

- `README.md` — quick orientation and the design-doc pointer.
- `aivyx/docs/superpowers/specs/2026-09-05-injection-guard-design.md` — the
  full design: why this was extracted, and how each of the two consumers
  (`aivyx-coder`, `aivyx`) integrates it differently.
