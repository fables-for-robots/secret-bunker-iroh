//! Relay-health instrumentation for the authoritative server.
//!
//! Two watchdogs against the failure mode where the endpoint quietly
//! re-homes to a different relay while its published discovery record
//! keeps advertising the old one — leaving every non-LAN peer dialing a
//! relay the server no longer listens on, indefinitely:
//!
//! - [`spawn_relay_status_log`] logs every home-relay transition, so a
//!   re-home is visible in the server log the moment it happens.
//! - [`spawn_record_self_check`] periodically resolves the server's own
//!   discovery record and warns when no advertised relay matches a
//!   relay the endpoint is actually connected to.

use std::time::Duration;

use iroh::address_lookup::dns::N0_DNS_ENDPOINT_ORIGIN_PROD;
use iroh::endpoint::RelayStatus;
use iroh::{Endpoint, RelayUrl, Watcher as _};
use tokio::sync::mpsc;

/// Which watchdog concluded the endpoint is wedged (iroh#4476) and needs
/// rebinding. Sent at most once per watchdog per endpoint generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WedgeReason {
    /// [`spawn_relay_down_watch`]: had a relay, none connected for
    /// [`RELAY_DOWN_REBIND_AFTER`].
    RelayDown,
    /// [`spawn_record_self_check`]: [`MISMATCH_REBIND_THRESHOLD`]
    /// consecutive self-checks saw the published record advertising no
    /// connected relay.
    RecordMismatch,
}

/// One line per relay: `<url> (connected)` / `<url> (down: <err>)`.
fn describe_statuses(statuses: &[RelayStatus]) -> String {
    if statuses.is_empty() {
        return "none".into();
    }
    statuses
        .iter()
        .map(|s| {
            if s.is_connected() {
                format!("{} (connected)", s.url())
            } else {
                match s.last_error() {
                    Some(err) => format!("{} (down: {err})", s.url()),
                    None => format!("{} (connecting)", s.url()),
                }
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Logs the home-relay set on start and on every change: `info` while at
/// least one relay is connected, `warn` when none is. The task ends when
/// the endpoint shuts down (the watcher disconnects).
pub fn spawn_relay_status_log(endpoint: &Endpoint) {
    let mut watcher = endpoint.home_relay_status();
    tokio::spawn(async move {
        let mut last: Option<String> = None;
        loop {
            let statuses = watcher.get();
            let desc = describe_statuses(&statuses);
            if last.as_deref() != Some(desc.as_str()) {
                if statuses.iter().any(|s| s.is_connected()) {
                    tracing::info!(relays = %desc, "home relay status");
                } else {
                    tracing::warn!(relays = %desc, "no home relay connected");
                }
                last = Some(desc);
            }
            if watcher.updated().await.is_err() {
                return;
            }
        }
    });
}

/// How many consecutive failed lookups of our own record before the
/// failure itself is worth a `warn`: one or two are DNS weather, a
/// streak means the record is gone or the resolver path is broken.
const LOOKUP_FAILURES_BEFORE_WARN: u32 = 3;

/// Every `interval`, resolves this endpoint's own discovery record from
/// the n0 DNS origin and warns when the advertised relays don't include
/// one we are actually connected to (see [`record_mismatch`]). After
/// [`MISMATCH_REBIND_THRESHOLD`] consecutive mismatches the state is a
/// wedge, not weather: the task escalates once and ends.
pub fn spawn_record_self_check(
    endpoint: &Endpoint,
    interval: Duration,
    escalate: mpsc::Sender<WedgeReason>,
) {
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        let mut failed_lookups: u32 = 0;
        let mut streak = MismatchStreak::new(MISMATCH_REBIND_THRESHOLD);
        loop {
            tokio::time::sleep(interval).await;
            let Ok(resolver) = endpoint.dns_resolver() else {
                return; // endpoint is shutting down
            };
            match resolver
                .lookup_endpoint_by_id(&endpoint.id(), N0_DNS_ENDPOINT_ORIGIN_PROD)
                .await
            {
                Ok(info) => {
                    failed_lookups = 0;
                    let advertised: Vec<RelayUrl> = info.data.relay_urls().cloned().collect();
                    let live: Vec<(RelayUrl, bool)> = endpoint
                        .home_relay_status()
                        .get()
                        .iter()
                        .map(|s| (s.url().clone(), s.is_connected()))
                        .collect();
                    match record_mismatch(&advertised, &live) {
                        Some(msg) => {
                            tracing::warn!("{msg}");
                            if streak.observe(Observation::Mismatch) {
                                tracing::warn!(
                                    consecutive = MISMATCH_REBIND_THRESHOLD,
                                    "record mismatch persists — escalating for an endpoint rebind"
                                );
                                let _ = escalate.try_send(WedgeReason::RecordMismatch);
                                return;
                            }
                        }
                        None => {
                            streak.observe(Observation::Match);
                            tracing::debug!(
                                relays = ?advertised.iter().map(|u| u.to_string()).collect::<Vec<_>>(),
                                "published discovery record matches a connected relay"
                            );
                        }
                    }
                }
                Err(err) => {
                    streak.observe(Observation::Inconclusive);
                    failed_lookups += 1;
                    if failed_lookups >= LOOKUP_FAILURES_BEFORE_WARN {
                        tracing::warn!(
                            %err,
                            consecutive = failed_lookups,
                            "cannot resolve our own discovery record — it may have expired"
                        );
                    } else {
                        tracing::debug!(%err, "own discovery record lookup failed");
                    }
                }
            }
        }
    });
}

/// How often [`spawn_relay_down_watch`] samples the home-relay set.
const RELAY_DOWN_SAMPLE_INTERVAL: Duration = Duration::from_secs(30);

/// Watches for the endpoint losing its home relay and not getting one
/// back (see [`RelayDownTracker`] for the exact semantics): escalates
/// once for an endpoint rebind, then ends. Also ends quietly when the
/// endpoint closes (a rebind spawns a fresh watch on the new endpoint).
pub fn spawn_relay_down_watch(
    endpoint: &Endpoint,
    down_after: Duration,
    escalate: mpsc::Sender<WedgeReason>,
) {
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        let mut tracker = RelayDownTracker::new(down_after);
        loop {
            if endpoint.is_closed() {
                return;
            }
            let any_connected = endpoint
                .home_relay_status()
                .get()
                .iter()
                .any(|s| s.is_connected());
            if tracker.observe(any_connected, std::time::Instant::now()) {
                tracing::warn!(
                    down_for = ?down_after,
                    "no home relay connected for too long — escalating for an endpoint rebind"
                );
                let _ = escalate.try_send(WedgeReason::RelayDown);
                return;
            }
            tokio::time::sleep(RELAY_DOWN_SAMPLE_INTERVAL).await;
        }
    });
}

/// How long the endpoint may sit with no connected home relay — after
/// having had one — before the serve loop should rebind it. Ten minutes
/// is far past any healthy reconnect (they complete in seconds; see the
/// 2026-08-17 incident log) yet quick next to the 15-hour outage a wedge
/// causes unattended.
pub const RELAY_DOWN_REBIND_AFTER: Duration = Duration::from_secs(10 * 60);

/// Consecutive mismatched record self-checks (at the 5-minute interval)
/// before escalating: one is DNS/registry propagation weather, three in a
/// row (~15 min) is a peer-visible outage.
pub(crate) const MISMATCH_REBIND_THRESHOLD: u32 = 3;

/// Tracks "the endpoint HAD a relay and has been without one too long".
///
/// Firing requires a prior connected relay on this endpoint: a fresh
/// endpoint that never reaches any relay looks identical to a dead
/// uplink (offline LAN deployment), and rebinding there would cut live
/// LAN connections every cycle for nothing. The record self-check covers
/// the wedge-at-bind case instead — a successful lookup of our own
/// record proves the internet path works.
pub struct RelayDownTracker {
    down_after: Duration,
    was_connected: bool,
    down_since: Option<std::time::Instant>,
}

impl RelayDownTracker {
    pub fn new(down_after: Duration) -> Self {
        RelayDownTracker {
            down_after,
            was_connected: false,
            down_since: None,
        }
    }

    /// Feed one sample of "is any home relay connected"; returns true
    /// when the endpoint should be rebound.
    pub fn observe(&mut self, any_connected: bool, now: std::time::Instant) -> bool {
        if any_connected {
            self.was_connected = true;
            self.down_since = None;
            return false;
        }
        if !self.was_connected {
            return false;
        }
        let since = *self.down_since.get_or_insert(now);
        now.duration_since(since) >= self.down_after
    }
}

/// One record self-check's verdict, as [`MismatchStreak`] counts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// An advertised relay is connected: healthy.
    Match,
    /// The record points at no connected relay: peers cannot reach us.
    Mismatch,
    /// The lookup itself failed — no evidence either way.
    Inconclusive,
}

/// Counts consecutive [`Observation::Mismatch`] verdicts; fires at the
/// threshold. Inconclusive lookups neither extend nor reset the streak.
pub struct MismatchStreak {
    threshold: u32,
    n: u32,
}

impl MismatchStreak {
    pub fn new(threshold: u32) -> Self {
        MismatchStreak { threshold, n: 0 }
    }

    /// Record one self-check outcome; returns true when the streak
    /// reaches the threshold.
    pub fn observe(&mut self, obs: Observation) -> bool {
        match obs {
            Observation::Match => self.n = 0,
            Observation::Mismatch => self.n += 1,
            Observation::Inconclusive => {}
        }
        self.n >= self.threshold
    }
}

/// Compares the relays a discovery record advertises against the live
/// home-relay state `(url, is_connected)`. Returns a warning message
/// when a remote peer following the record could not reach us — i.e.
/// when no advertised relay is currently connected — and `None` when
/// at least one is.
pub fn record_mismatch(advertised: &[RelayUrl], live: &[(RelayUrl, bool)]) -> Option<String> {
    if advertised.is_empty() {
        return Some("published discovery record advertises no relay".into());
    }
    let reachable = advertised
        .iter()
        .any(|adv| live.iter().any(|(url, connected)| *connected && url == adv));
    if reachable {
        return None;
    }
    let advertised: Vec<String> = advertised.iter().map(|u| u.to_string()).collect();
    let connected: Vec<String> = live
        .iter()
        .filter(|(_, up)| *up)
        .map(|(u, _)| u.to_string())
        .collect();
    Some(format!(
        "published discovery record advertises relay(s) [{}] but connected relay(s) are [{}] — \
         remote peers following the record cannot reach us",
        advertised.join(", "),
        connected.join(", "),
    ))
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    fn url(s: &str) -> RelayUrl {
        s.parse().expect("relay url")
    }

    fn t(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn never_connected_endpoint_never_triggers_relay_down() {
        let base = Instant::now();
        let mut tr = RelayDownTracker::new(Duration::from_secs(600));
        assert!(!tr.observe(false, t(base, 0)));
        assert!(
            !tr.observe(false, t(base, 6000)),
            "no prior relay: must not fire"
        );
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
        // The outage clock restarts at the first down sample after the
        // reconnect (700), not at the reconnect itself.
        assert!(!tr.observe(false, t(base, 700)), "clock restarted");
        assert!(
            !tr.observe(false, t(base, 1299)),
            "1s short of the restarted threshold"
        );
        assert!(tr.observe(false, t(base, 1300)));
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
        assert!(
            s.observe(Observation::Mismatch),
            "inconclusive neither reset nor advanced"
        );
    }

    const USE1: &str = "https://use1-1.relay.n0.iroh.link./";
    const EUC1: &str = "https://euc1-1.relay.n0.iroh.link./";
    const APS1: &str = "https://aps1-1.relay.n0.iroh.link./";

    #[test]
    fn advertised_relay_connected_is_healthy() {
        let out = record_mismatch(&[url(EUC1)], &[(url(EUC1), true)]);
        assert_eq!(out, None);
    }

    #[test]
    fn advertised_relay_differs_from_connected_relay_warns() {
        // The Aug 2026 incident: record says use1-1, endpoint lives on aps1-1.
        let out = record_mismatch(&[url(USE1)], &[(url(APS1), true)]);
        let msg = out.expect("mismatch must warn");
        assert!(msg.contains("use1-1"), "names the advertised relay: {msg}");
        assert!(msg.contains("aps1-1"), "names the live relay: {msg}");
    }

    #[test]
    fn record_without_any_relay_warns() {
        let out = record_mismatch(&[], &[(url(EUC1), true)]);
        assert!(out.is_some());
    }

    #[test]
    fn advertised_relay_present_but_disconnected_warns() {
        let out = record_mismatch(&[url(EUC1)], &[(url(EUC1), false)]);
        assert!(out.is_some());
    }

    #[test]
    fn one_of_several_advertised_relays_connected_is_healthy() {
        let out = record_mismatch(
            &[url(USE1), url(EUC1)],
            &[(url(EUC1), true), (url(APS1), true)],
        );
        assert_eq!(out, None);
    }
}
