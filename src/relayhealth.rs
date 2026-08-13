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
/// one we are actually connected to (see [`record_mismatch`]).
pub fn spawn_record_self_check(endpoint: &Endpoint, interval: Duration) {
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        let mut failed_lookups: u32 = 0;
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
                        Some(msg) => tracing::warn!("{msg}"),
                        None => tracing::debug!(
                            relays = ?advertised.iter().map(|u| u.to_string()).collect::<Vec<_>>(),
                            "published discovery record matches a connected relay"
                        ),
                    }
                }
                Err(err) => {
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
    use super::*;

    fn url(s: &str) -> RelayUrl {
        s.parse().expect("relay url")
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
