# bicameral

**Concurrence for minds with more than one chamber — signed ballots, constitutional rules, preserved dissent.**

A dual-brained organism is two reasoning faculties under one sovereignty, not one opinion with a coprocessor. `bicameral` tables consequential questions as *motions*, each chamber casts a signed vote under its own key, and the motion resolves under a rule — `Unanimous`, `Majority`, or `Any`.

## The point

When the chambers split, nothing is smoothed over. The split is sealed as a `DissentRecord` — both positions, both signatures — permanently inside the `Hansard`, a hash-chained parliamentary record. An organism that can formally disagree with itself is *more* trustworthy than one faking unanimity: the dissent is the receipt that the vote was real.

## What it gives you

- `Chamber` — name bound to an Ed25519 key; each faculty signs its own ballots, so no chamber can fabricate another's position.
- `Motion` — tabled questions, optional deadlines that fail closed.
- `Ballot` — signed vote + hash of the chamber's reasoning (reasoning stays internal; the hash proves what was weighed).
- `Hansard` — hash-chained record: motions, ballots, resolutions, dissent. Its head is notarizable by `kola` witnesses.
- Resolution semantics: `Unanimous`/`Majority` wait for all seated chambers (closing early would erase positions); `Any` resolves on first Aye for advisory use.
- Fails closed: expired deadlines, unseated signers, duplicate ballots, forged entries — all rejected.

## Try it

```bash
cargo run --example session
cargo test
```

## Pair with

- `kola` — notarize the hansard head so even dissent history is unforgeable.
- `wolakota` — treaty ratification as a motion both chambers must carry.
- `nagi` — custodian rotation ceremonies gated on concurrence.
