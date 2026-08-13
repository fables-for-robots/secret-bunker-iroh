//! Connection path logging: whether a connection runs direct (IP) or
//! over a relay server, at connect time and whenever the selected
//! transmission path changes afterwards — typically holepunching
//! upgrading a relayed connection to a direct one.

use iroh::TransportAddr;
use iroh::endpoint::{Connection, PathEvent};
use tokio_stream::StreamExt;

/// Human-readable form of one transport address: `direct <ip:port>` or
/// `relay <url>`.
fn describe(addr: &TransportAddr) -> String {
    match addr {
        TransportAddr::Ip(addr) => format!("direct {addr}"),
        TransportAddr::Relay(url) => format!("relay {url}"),
        // TransportAddr is non_exhaustive (Custom today).
        other => format!("{other:?}"),
    }
}

/// The connection's currently selected transmission path.
pub(crate) fn selected_path(conn: &Connection) -> String {
    conn.paths()
        .iter()
        .find(|p| p.is_selected())
        .map(|p| describe(p.remote_addr()))
        .unwrap_or_else(|| "none yet".into())
}

/// Log every later change of the selected path; `peer` identifies the
/// connection in the log line. The spawned task ends with the
/// connection: `path_events` does not keep it alive and its stream
/// closes when the connection does.
pub(crate) fn log_path_changes(conn: &Connection, peer: String) {
    // Subscribe before snapshotting, so a selection landing in between
    // is seen as an event rather than lost.
    let mut events = conn.path_events();
    let mut last: Option<TransportAddr> = conn
        .paths()
        .iter()
        .find(|p| p.is_selected())
        .map(|p| p.remote_addr().clone());
    tokio::spawn(async move {
        while let Some(event) = events.next().await {
            // Opened/Closed track candidate paths, not the one in use,
            // and after Lagged the next Selected still arrives.
            if let PathEvent::Selected { remote_addr, .. } = event
                && last.as_ref() != Some(&remote_addr)
            {
                tracing::info!(
                    peer,
                    path = describe(&remote_addr),
                    "connection path changed"
                );
                last = Some(remote_addr);
            }
        }
    });
}
