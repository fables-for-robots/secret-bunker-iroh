# Working context for the signed-epochs design (2026-09-07)

This directory preserves the material behind
[`../../specs/2026-09-07-signed-epochs-design.md`](../../specs/2026-09-07-signed-epochs-design.md)
so the design can be continued, questioned or re-derived without the original
session. The spec is the deliverable; everything here is evidence and history.

**Status at the time of writing:** the spec is a draft awaiting the user's answers
to its section 19 (16 open questions). No implementation plan exists yet; the
next step after approval is an implementation plan (`superpowers:writing-plans`).

## How the spec was produced

1. **Ask.** Design a system using Chaum-Pedersen/DLEQ so that every group admin
   can kick users and roll the group's single random data key without the
   "master admin" (the server's operational key / the service admin), with a
   record of who last re-encrypted. Background: SOPS's "every key holder is an
   anonymous author" weakness and the idea of an algebraic, publicly verifiable
   multi-recipient wrap. See `brief.md`.
2. **Numeric probe** (`probe/`). A throwaway Rust program against the real
   `curve25519-dalek 5` / `ed25519-dalek 3` crates, using real Ed25519 keys,
   checked the construction before anything was written. It confirmed the batched
   proof and the torsion-grinding attack it must defend against, and — decisively —
   that with a *shared* nonce a registered key equal to `−A` of another reader
   leaks the data key to everyone from the public record. `probe/RESULTS.md` has
   both runs' output.
3. **Design panel** (`designs/`, `critiques/`, `gaps.json`). Four independent
   designers wrote complete designs from different angles: `crypto` (the
   cryptographer), `systems` (integration into this codebase), `governance`
   (authorization rules and threat model), `e2e` (the end-to-end purist, arguing
   against itself). Each design was attacked by three critics with different
   lenses (`<designer>-crypto-soundness`, `-authz-logic`, `-impl-fit`). A
   completeness critic then compared all four and their critiques and recommended
   a synthesis (`gaps.json`: missing topics, contradictions between designs with
   a ruling on each, best ideas to keep, questions for the user).
4. **Synthesis.** The spec was written by hand from the governance design's rule
   system, the cryptographer's primitive specification, the systems design's
   integration engineering and the critique consensus, with one deliberate
   deviation from the panel: per-recipient randomness instead of a shared nonce
   plus proof-of-possession (spec D1, justified by the probe).
5. **Three adversarial review rounds on the written spec** (`review1/`,
   `review2/`, `review3/`), each followed by a full revision:
   - Round 1 (six skeptics, two per lens, plus a consistency critic) found five
     criticals and about thirty majors, among them: the migration's genesis
     generation number contradicted the verifier rule; the schema used an
     `ALTER TABLE … ADD COLUMN … UNIQUE` that SQLite rejects; the recovery flow
     was blocked by its own staging gates; a delete-then-recreate race could
     install stale plaintext; an admin could rotate itself out while keeping the
     new key; unpinned replicas accepted a re-genesis; the phase plan froze all
     grants for one release.
   - Round 2 (one skeptic per lens plus consistency) found no criticals and
     eleven majors, mostly collisions between the newly added rules (the rate
     limit and freeze applying to the server's own revocations, the recovery
     rule refusing backup-key replacement, the stuck-RNG hedge indexing by sort
     position, the two-key operational-key handover described three ways).
   - Round 3 (an authorization skeptic and a consistency critic, both focused on
     what round 2 changed) found no criticals and ten majors; the largest
     simplification came out of it: with the write fence starting at `OpenStage`
     and a snapshot taken there, server-side "straggler" re-encryption is
     unnecessary and was removed.

The spec's section 2 (decisions with rejected alternatives) records the outcome
of all of this; its section 19 lists the decisions only the user can make.

## Layout

| Path | What it is |
|---|---|
| `brief.md` | The brief handed to the panel: the ask, the background, the current system, a preliminary skeleton, the questions every design had to answer |
| `designs/{crypto,systems,governance,e2e}.md` | The four independent panel designs, each followed by its key decisions, risks and open questions |
| `critiques/<designer>-<lens>.json` | Twelve adversarial critiques of the panel designs (`findings` with severity/detail/fix, `strengths`, `verdict`) |
| `gaps.json` | The completeness critic's cross-design synthesis and recommended shape for the spec |
| `review1/{crypto,authz,implfit}-{A,B}.json`, `review1/consistency.json` | First review round of the written spec |
| `review2/{crypto,authz,implfit,consistency}.json` | Second round (each lists `unfixed_prior` items and new `findings`) |
| `review3/{authz,consistency}.json` | Third, final round |
| `probe/` | The throwaway numeric probe (source and results); build standalone, then delete `target/` |

The critique and review files are machine output written by review agents. They
are kept verbatim: findings are ranked most-severe first and each carries a
concrete scenario and a proposed fix, so they double as a checklist when the spec
is next revised. Where a finding contradicts the current spec, the spec is the
resolution (every finding of all three rounds was either applied or superseded by
a later revision).

## What was decided on the user's behalf (to confirm or overturn)

The assumptions the spec currently rests on, each flagged in its section 19:
mode A (server stays a recipient) is the only built mode; the Go client uses only
data operations; admins may kick admins; admin implies read; rotation
re-encrypts every retained version; a fresh offline Ed25519 backup key; recovery
of an orphaned group only via that key; write fences during rotations and after
server-side revocations; rejection of rewound chains with an explicit pin reset;
signed puts deferred; one maintenance window for migration; disclosure of
EndpointIds to group admins and of the chain to readers; the legacy `Grant`
shrink path kept; explicit admin rows for service admins at migration; a 4 KiB
reduction of the maximum `Put` value; keyed (not per-name) replica genesis
admission.
