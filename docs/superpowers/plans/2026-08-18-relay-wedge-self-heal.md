# Relay-Wedge Self-Heal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When the iroh endpoint's relay state wedges (iroh#4476), the `serve` process detects it and rebinds endpoint + router in-process, restoring reachability without a restart.

**Architecture:** Pure decision logic (`RelayDownTracker`, `MismatchStreak`) in `relayhealth.rs` feeds a bounded mpsc wedge channel from two per-generation watchdog tasks; a new `serveloop::serve_with_rebind` loop owns build/teardown of each serving generation; `main.rs` serve paths (authoritative and replica) become build closures.

**Tech Stack:** Rust 2024, tokio, iroh 1.0.3 (`Router`, `Endpoint`, `home_relay_status`, DNS record lookup).

**Spec:** `docs/superpowers/specs/2026-08-18-relay-wedge-self-heal-design.md`

## Global Constraints

- Never exit the process on wedge — rebind only (decision in spec).
- Triggers armed only when `!no_relay`.
- `RELAY_DOWN_REBIND_AFTER` = 10 min; relay-down trigger requires a prior connected relay on this endpoint.
- `MISMATCH_REBIND_THRESHOLD` = 3 consecutive mismatched self-checks; failed lookups neither extend nor reset the streak.
- Store opens once (authoritative); same EndpointId across generations.
- First-generation build failure fatal; later failures retry forever (30 s prod delay, parameterized for tests).
- `cargo fmt` clean (CI checks it); all existing tests keep passing.

---

### Task 1: Pure detection logic in relayhealth

**Files:**
- Modify: `src/relayhealth.rs` (add types + tests; no signature changes yet)

**Interfaces:**
- Produces: `pub struct RelayDownTracker { fn new(down_after: Duration) -> Self; fn observe(&mut self, any_connected: bool, now: Instant) -> bool }`
- Produces: `pub enum Observation { Match, Mismatch, Inconclusive }`, `pub struct MismatchStreak { fn new(threshold: u32) -> Self; fn observe(&mut self, obs: Observation) -> bool }`
- Produces: `pub const RELAY_DOWN_REBIND_AFTER: Duration`, `pub(crate) const MISMATCH_REBIND_THRESHOLD: u32 = 3`

- [ ] **Step 1: Write failing unit tests** (append to `relayhealth::tests`)

```rust
fn t(base: Instant, secs: u64) -> Instant { base + Duration::from_secs(secs) }

#[test]
fn never_connected_endpoint_never_triggers_relay_down() {
    let base = Instant::now();
    let mut tr = RelayDownTracker::new(Duration::from_secs(600));
    assert!(!tr.observe(false, t(base, 0)));
    assert!(!tr.observe(false, t(base, 6000)), "no prior relay: must not fire");
}

#[test]
fn relay_down_triggers_after_threshold_once_connected() {
    let base = Instant::now();
    let mut tr = RelayDownTracker::new(Duration::from_secs(600));
    assert!(!tr.observe(true, t(base, 0)));
    assert!(!tr.observe(false, t(base, 10)));
    assert!(!tr.observe(false, t(base, 609)), "1s short of threshold");
    assert!(tr.observe(false, t(base, 610)));
}

#[test]
fn reconnect_resets_the_relay_down_clock() {
    let base = Instant::now();
    let mut tr = RelayDownTracker::new(Duration::from_secs(600));
    tr.observe(true, t(base, 0));
    tr.observe(false, t(base, 10));
    tr.observe(true, t(base, 300)); // came back
    assert!(!tr.observe(false, t(base, 700)), "clock restarted at 300+");
    assert!(tr.observe(false, t(base, 901)));
}

#[test]
fn mismatch_streak_fires_at_threshold() {
    let mut s = MismatchStreak::new(3);
    assert!(!s.observe(Observation::Mismatch));
    assert!(!s.observe(Observation::Mismatch));
    assert!(s.observe(Observation::Mismatch));
}

#[test]
fn a_match_resets_the_streak() {
    let mut s = MismatchStreak::new(3);
    s.observe(Observation::Mismatch);
    s.observe(Observation::Mismatch);
    assert!(!s.observe(Observation::Match));
    assert!(!s.observe(Observation::Mismatch));
    assert!(!s.observe(Observation::Mismatch));
    assert!(s.observe(Observation::Mismatch));
}

#[test]
fn inconclusive_lookups_freeze_the_streak() {
    let mut s = MismatchStreak::new(3);
    s.observe(Observation::Mismatch);
    s.observe(Observation::Mismatch);
    assert!(!s.observe(Observation::Inconclusive));
    assert!(s.observe(Observation::Mismatch), "inconclusive neither reset nor advanced");
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p secret-bunker-iroh --lib relayhealth` → compile error (types missing).
- [ ] **Step 3: Implement** `RelayDownTracker` (`down_after`, `was_connected: bool`, `down_since: Option<Instant>`; observe: connected → `was_connected=true, down_since=None`, ret false; !connected && was_connected → `down_since.get_or_insert(now)`, ret `now - down_since >= down_after`; !was_connected → ret false) and `MismatchStreak` (Match → n=0; Mismatch → n+=1; Inconclusive → no-op; ret `n >= threshold`). Add the two consts.
- [ ] **Step 4: Run to verify pass** — same command, all relayhealth tests green.
- [ ] **Step 5: Commit** — `feat(relayhealth): pure wedge-detection state machines`

### Task 2: Wedge channel + watchdog wiring

**Files:**
- Modify: `src/relayhealth.rs` (new `WedgeReason`, `spawn_relay_down_watch`; `spawn_record_self_check` gains `escalate` param)
- Modify: `src/main.rs` (call site passes a throwaway channel for now — replaced in Task 4)

**Interfaces:**
- Produces: `pub enum WedgeReason { RelayDown, RecordMismatch }` (Debug, Clone, Copy, PartialEq, Eq)
- Produces: `pub fn spawn_relay_down_watch(endpoint: &Endpoint, down_after: Duration, escalate: mpsc::Sender<WedgeReason>)`
- Changes: `pub fn spawn_record_self_check(endpoint: &Endpoint, interval: Duration, escalate: mpsc::Sender<WedgeReason>)`

- [ ] **Step 1:** Add `WedgeReason`. Add `spawn_relay_down_watch`: tokio task, `RelayDownTracker::new(down_after)`, loop { if `endpoint.is_closed()` return; sample `home_relay_status().get()` any-connected; if `tracker.observe(any, Instant::now())` { `tracing::warn!` naming the trigger; `let _ = escalate.try_send(WedgeReason::RelayDown);` return } ; sleep 30 s }.
- [ ] **Step 2:** Extend `spawn_record_self_check`: hold a `MismatchStreak::new(MISMATCH_REBIND_THRESHOLD)`; Ok+mismatch → warn (as today) + `observe(Mismatch)`, fire+return on true; Ok+match → `observe(Match)`; Err → `observe(Inconclusive)` (keep today's failed-lookup logging).
- [ ] **Step 3:** Fix the `main.rs` call site minimally (temporary `let (tx, _rx) = mpsc::channel(2);`) so the crate compiles.
- [ ] **Step 4:** `cargo test --lib` green, `cargo build` green.
- [ ] **Step 5: Commit** — `feat(relayhealth): escalate persistent wedge over a channel`

### Task 3: serveloop::serve_with_rebind

**Files:**
- Create: `src/serveloop.rs`
- Modify: `src/lib.rs` (add `pub mod serveloop;`)

**Interfaces:**
- Produces:
```rust
pub struct Generation {
    pub router: iroh::protocol::Router,
    pub wedged: Option<tokio::sync::mpsc::Receiver<WedgeReason>>,
    pub teardown: Option<std::pin::Pin<Box<dyn Future<Output = ()> + Send>>>,
}
pub async fn serve_with_rebind<B, BFut, S>(
    build: B, shutdown: S, rebuild_retry: Duration,
) -> anyhow::Result<()>
where B: FnMut(u64) -> BFut, BFut: Future<Output = anyhow::Result<Generation>>, S: Future<Output = ()>;
```

- [ ] **Step 1: Write failing in-module tokio tests** (Minimal preset; store/Bunker setup as in `tests/e2e.rs::init_store`; clients via `Client::with_endpoint`): (a) `wedge_signal_rebinds_and_serves_again` — build closure records each generation's `EndpointAddr` + wedge `Sender` in shared Vecs; gen 1: admin `CreateGroup "g"` → Ok; fire `WedgeReason::RelayDown`; poll until gen 2 addr appears; `ListGroups` on new addr → sees `g`; same `EndpointId`; shutdown via oneshot-backed future → loop returns Ok. (b) `shutdown_with_no_wedge_is_clean` — one generation, immediate shutdown, Ok, build called once. (c) `first_build_failure_is_fatal` — closure returns Err → serve_with_rebind Err. (d) `rebuild_failure_retries_until_success` — gen 2 Err once then gen 3 Ok, `rebuild_retry`=50 ms; serving works on gen 3.
- [ ] **Step 2:** Run → compile failure (module missing).
- [ ] **Step 3: Implement** the loop: `tokio::pin!(shutdown)`; generation counter; build with first-gen-fatal / later-retry-with-delay; `select!` on `&mut shutdown` vs wedge recv (a `None` recv — channel absent or all senders gone — pends forever instead of looping); on wedge: warn with reason + generation, `router.shutdown()` (log error, continue), await `teardown` if present, loop; on shutdown: same teardown sequence, return Ok.
- [ ] **Step 4:** `cargo test --lib serveloop` green.
- [ ] **Step 5: Commit** — `feat(serveloop): self-healing serve loop with endpoint rebind`

### Task 4: Wire the authoritative serve path

**Files:**
- Modify: `src/main.rs` (authoritative branch of `Cmd::Serve`; remove Task 2's throwaway channel)

- [ ] **Step 1:** Replace the one-shot endpoint/router construction with `serve_with_rebind` (30 s rebuild retry). Build closure per generation: `bind_serve_endpoint(secret.clone(), no_relay, no_mdns)`; gen 1 prints endpoint id + bound sockets (unchanged UX), later gens `tracing::warn!(generation, "endpoint wedged — rebound over a fresh endpoint")`; Router accepts `proto::ALPN` (bunker.clone()) + `SYNC_ALPN` (bunker.sync_handler()); if `!no_relay`: 15 s `online()` wait with the existing messages, `spawn_relay_status_log`, `spawn_relay_down_watch(…, RELAY_DOWN_REBIND_AFTER, tx)`, `spawn_record_self_check(…, 300 s, tx)`, `wedged: Some(rx)`; else `wedged: None`. Shutdown future: `ctrl_c().await` then `eprintln!("shutting down")`.
- [ ] **Step 2:** `cargo build` + `cargo test` (bin compiles; cli tests pass).
- [ ] **Step 3: Commit** — `feat(serve): self-heal the authoritative endpoint on relay wedge`

### Task 5: Wire the replica serve path

**Files:**
- Modify: `src/main.rs` (replica branch of `Cmd::Serve`)

- [ ] **Step 1:** Same loop: build closure binds endpoint (gen 1 prints replica id + bound as today), spawns `Replica::builder()…endpoint(endpoint.clone())` per generation, Router accepts `proto::ALPN` with `replica.protocol_handler()`; watchdogs as Task 4 (record self-check included — the replica publishes a record for its own clients); `teardown: Some(Box::pin(async move { replica.shutdown().await }))` (ordering per the existing comment: router first, replica after).
- [ ] **Step 2:** `cargo build` + full `cargo test` (e2e replica tests must stay green).
- [ ] **Step 3: Commit** — `feat(serve): self-heal the replica endpoint on relay wedge`

### Task 6: Full verification

- [ ] `cargo fmt` (CI gate), `cargo clippy --all-targets` if clean today, full `cargo test` including `tests/e2e.rs` + `tests/cli.rs`.
- [ ] Commit any fmt fallout; branch ready for morning review.

### Ops (post-plan, tonight)

1. Build the branch; `tmux send-keys -t 0:3.0 C-c`, wait for exit, relaunch `target/debug/secret-bunker-iroh serve --db bunker-db` in the same pane.
2. Watch for: `online: reachable via relay`, home relay `(connected)`, DNS record matching the connected relay, and `sync client ce683d0616…` reconnecting (replica backoff cap is 60 s).
3. Report findings for the morning.
