# SPEC — bicameral (dual-brain concurrence)

## Chambers

Chambers are independent signing identities (`Identity`, ed25519) seated
by name — conventionally `gpu` and `ane`. A chamber's key is its vote;
the seat is established by `seat(identity)`.

## Motion

`table(subject, origin)` opens a motion. A motion is `Open` until every
seated chamber has cast a ballot.

## Ballot

```json
{
  "motion_id": "…",
  "chamber": "gpu|ane|…",
  "vote": "aye|nay|abstain",
  "reason": "free text",
  "ts": 0,
  "signature": "ed25519 over canonical ballot body"
}
```

## Resolution

- All ballots in **and** all Aye → `Passed`.
- Any Nay → `Dissent` — resolution waits for the full ballot set so the
  complete chamber split is on the record, then fails closed.
- Abstain counts toward quorum but not toward passage — a motion with
  abstentions and Ayes resolves `Dissent` unless the hansard policy says
  otherwise (default: abstain ≠ aye → dissent).

## Hansard

Every event — `MotionTabled`, `VoteCast`, `Resolved`, `DissentRecorded`
— is a hash-chained `HansardEntry`. `verify()` checks linkage and all
signatures offline.

## Invariants

- No resolution before all ballots (dissent cannot be hidden by speed).
- Fail closed: Nay anywhere ⇒ motion does not pass.
- Votes are attributed by signature — a chamber cannot disown its ballot.
