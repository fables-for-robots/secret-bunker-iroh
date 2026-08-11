//! Prometheus metrics per the spec's observability section.

use prometheus::{Histogram, HistogramOpts, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry};

#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    pub connected: IntGauge,
    pub last_sync_ts: IntGauge,
    pub groups: IntGauge,
    pub events_total: IntCounterVec,
    pub reconciles_total: IntCounterVec,
    pub reconcile_duration: Histogram,
    pub applies_total: IntCounterVec,
    pub ready: IntGaugeVec,
}

impl Metrics {
    pub fn new() -> anyhow::Result<Metrics> {
        let registry = Registry::new();
        let connected = IntGauge::new(
            "bunker_replica_connected",
            "1 when the sync session to the authoritative bunker is up",
        )?;
        let last_sync_ts = IntGauge::new(
            "bunker_replica_last_sync_timestamp_seconds",
            "Unix time of the last completed sync; 0 before the first",
        )?;
        let groups = IntGauge::new(
            "bunker_replica_groups",
            "Groups currently in the local mirror",
        )?;
        let events_total = IntCounterVec::new(
            Opts::new(
                "bunker_replica_events_total",
                "Replica events seen, by type",
            ),
            &["type"],
        )?;
        let reconciles_total = IntCounterVec::new(
            Opts::new("bunker_secret_reconciles_total", "Reconcile outcomes"),
            &["result"],
        )?;
        let reconcile_duration = Histogram::with_opts(
            HistogramOpts::new(
                "bunker_secret_reconcile_duration_seconds",
                "Reconcile duration",
            )
            .buckets(vec![0.001, 0.01, 0.1, 0.5, 2.0, 10.0]),
        )?;
        let applies_total = IntCounterVec::new(
            Opts::new("bunker_secret_applies_total", "Secret writes vs hash-skips"),
            &["outcome"],
        )?;
        let ready = IntGaugeVec::new(
            Opts::new(
                "bunker_secret_ready",
                "1 when the BunkerSecret's Ready condition is True",
            ),
            &["namespace", "name"],
        )?;
        for c in [
            Box::new(connected.clone()) as Box<dyn prometheus::core::Collector>,
            Box::new(last_sync_ts.clone()),
            Box::new(groups.clone()),
            Box::new(events_total.clone()),
            Box::new(reconciles_total.clone()),
            Box::new(reconcile_duration.clone()),
            Box::new(applies_total.clone()),
            Box::new(ready.clone()),
        ] {
            registry.register(c)?;
        }
        Ok(Metrics {
            registry,
            connected,
            last_sync_ts,
            groups,
            events_total,
            reconciles_total,
            reconcile_duration,
            applies_total,
            ready,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Encoder;

    #[test]
    fn all_metrics_register_and_render() {
        let m = Metrics::new().unwrap();
        m.connected.set(1);
        m.events_total.with_label_values(&["secret_changed"]).inc();
        m.reconciles_total.with_label_values(&["success"]).inc();
        m.reconcile_duration.observe(0.05);
        m.applies_total.with_label_values(&["applied"]).inc();
        m.ready.with_label_values(&["ns", "name"]).set(1);
        let mut buf = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&m.registry.gather(), &mut buf)
            .unwrap();
        let text = String::from_utf8(buf).unwrap();
        for name in [
            "bunker_replica_connected",
            "bunker_replica_last_sync_timestamp_seconds",
            "bunker_replica_groups",
            "bunker_replica_events_total",
            "bunker_secret_reconciles_total",
            "bunker_secret_reconcile_duration_seconds",
            "bunker_secret_applies_total",
            "bunker_secret_ready",
        ] {
            assert!(text.contains(name), "missing {name} in:\n{text}");
        }
    }
}
