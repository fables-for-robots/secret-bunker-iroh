# Relay-Wedge Self-Heal — Design

**Date:** 2026-08-18
**Motivation:** Incident of 2026-08-17 (upstream: <https://github.com/n0-computer/iroh/issues/4476>).
The authoritative bunker's iroh endpoint re-homed relays at 07:08 UTC and got
permanently stuck: `home_relay_status()` reported `connecting` for 15+ hours
with no retry or fallback, while the published discovery record kept
advertising the unreachable relay. Every non-LAN peer (the shipyard replica
included) was unable to connect until a manual restart. The relayhealth
watchdogs (commit 92945bc) *detected* the state every 5 minutes but nothing
*acted* on it.

## Decision (made with Dragan, 2026-08-18)

- **In-process rebind only.** When the wedge is detected, tear down the
  Router (which closes its endpoint) and rebuild both over the same secret
  key and the same open store. Never exit the process; no supervisor
  dependency (deployment stays a tmux pane).
- Applies to the `serve` path — authoritative first (tonight's deploy),
  replica wired the same way.

## Detection

Two independent triggers, both only when relays are enabled (`!no_relay`):

1. **Relay-down**: the endpoint had a connected home relay at least once,
   then had *no* connected relay continuously for 10 minutes
   (`RELAY_DOWN_REBIND_AFTER`). The "connected at least once" guard keeps a
   LAN-only deployment with no internet from cycling every 10 minutes —
   a fresh endpoint that has never reached a relay is indistinguishable
   from a dead uplink, and rebinding cuts live LAN connections.
2. **Record mismatch**: the existing 5-minute record self-check (resolve our
   own discovery record, compare advertised relays against connected ones)
   reports a mismatch 3 consecutive times (`MISMATCH_REBIND_THRESHOLD`,
   ≈15 min). A successful DNS lookup proves the internet path works, so this
   trigger fires even on an endpoint that never got a relay connection —
   covering a wedge-at-bind. Failed lookups neither extend nor reset the
   streak (no evidence either way).

In the 2026-08-17 incident, trigger 2 would have healed the outage at
~07:25 instead of 15+ hours later; trigger 1 at ~07:18.

## Rebind mechanics

A generic supervisor loop `serveloop::serve_with_rebind(build, shutdown,
rebuild_retry)`:

- `build(generation)` binds the endpoint, builds the Router over the
  existing protocol handlers, spawns the relayhealth watchdogs wired to a
  wedge channel, and returns a `Generation { router, wedged, teardown }`.
- The loop waits for either `shutdown` (ctrl-c → shut the generation down,
  return) or a wedge signal (→ shut the generation down, run the optional
  `teardown` future, build the next generation).
- `Bunker` is `Arc`-shared and endpoint-free, so the store is opened once
  and survives every rebind. The replica path rebuilds the `Replica` per
  generation (its `teardown` is `replica.shutdown()`); the store role check
  re-runs harmlessly.
- First-generation build failure is fatal (startup errors stay loud);
  later build failures retry forever with a fixed delay (30 s in
  production), warning each time.
- Consequences of a rebind: new ports (discovery and mDNS republish),
  all live connections cut (remote ones are dead already in the wedged
  state; LAN clients reconnect). Same EndpointId throughout.

Detector tasks are per-generation: they exit when their endpoint closes or
after sending one wedge signal, so rebinds do not accumulate tasks.

## Out of scope

- `Endpoint::network_change()` "kick" before rebinding (rejected: it pokes
  the same wedged relay actor we no longer trust; the fresh endpoint is the
  clean-slate guarantee).
- Exiting for a supervisor to restart (rejected: no supervisor in the
  tmux deployment).
- New CLI flags for the thresholds (constants until someone needs them).
- The k8s operator's liveness probe story for a wedged replica.
