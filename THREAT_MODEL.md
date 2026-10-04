# Threat model — bicameral

One chamber is compromised — the other fails closed on Nay; a lone Aye cannot pass a consequential motion. A motion's history is rewritten — the hansard is hash-chained. Dissent is suppressed — resolution only commits after all ballots are in. A ballot is forged — ed25519 signature on the canonical ballot body.

## What this crate guarantees

- No consequential motion resolves before every seated chamber has voted.
- Any Nay resolves to Dissent — the split is preserved, signed, in the hansard.
- The hansard is append-only hash-chained; the record cannot be reordered or truncated.

## What it does not guarantee

- Protection against a verifier who never calls `verify()`.
- Integrity of inputs produced by other systems — this crate verifies
  signatures and chains over what it is given; garbage that verifies is
  still garbage.
