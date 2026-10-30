// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! `pms-telemetry-export`: Prometheus metrics for Pulse Mesh drivers.
//!
//! Publish rate, receive-latency distribution, slot occupancy, queue depth,
//! conflation ratio and wait-strategy mode, exposed as counters and
//! histograms that an existing Prometheus and Grafana setup scrapes without
//! new plumbing. Optimization module M08 in the module table.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/architecture/peripheral.html>.
#![forbid(unsafe_code)]

use prometheus::{Counter, Encoder, Gauge, Histogram, HistogramOpts, Opts, Registry, TextEncoder};
use std::sync::Arc;
use thiserror::Error;

/// Errors raised by [`Metrics`] construction or rendering.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum TelemetryExportError {
    /// Failed to render the metrics buffer into Prometheus text format.
    #[error("prometheus encode failed: {0}")]
    Encode(String),
    /// One of the canonical metrics failed to register against the
    /// Prometheus `Registry` — typically a duplicate-name collision when
    /// multiple `Metrics` instances share a registry.
    #[error("metric registration failed: {0}")]
    Register(#[from] prometheus::Error),
}

/// Canonical PMS metrics surface. Construct one per process (Arc-shareable).
pub struct Metrics {
    /// Underlying Prometheus registry. Exposed so callers can register their
    /// own application-specific metrics alongside PMS's canonical set.
    pub registry: Registry,
    /// Monotonic count of frames published since process start.
    pub publish_total: Counter,
    /// Per-receive latency histogram (nanoseconds). Bucketed for the typical
    /// PMS shm latency range (10ns – 100ms).
    pub recv_latency_ns: Histogram,
    /// Current slot-utilization fraction (0.0 – 1.0).
    pub slot_occupancy: Gauge,
    /// Compression ratio observed by the conflation drainer
    /// — `inbound_messages / unique_keys_emitted`.
    pub conflation_compression_ratio: Gauge,
    /// Active wait-strategy mode (encoded: 0=BusySpin, 1=UMWAIT, 2=Park).
    pub wait_strategy_mode: Gauge,
    /// Adaptive prefetch distance currently configured (M09 OPT #2).
    pub prefetch_distance: Gauge,
}

impl Metrics {
    /// Build a fresh registry + register all PMS metrics.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryExportError`] wrapping the underlying
    /// [`prometheus::Error`] if any metric constructor (`Counter`,
    /// `Histogram`, `Gauge`) rejects the supplied options — typically
    /// only on duplicate-name registration (structurally impossible
    /// in this constructor since the names are hard-coded distinct)
    /// or invalid histogram bucket boundaries. The `?` propagation
    /// short-circuits on first failure, leaving the partially-built
    /// registry to be dropped.
    pub fn new() -> Result<Arc<Self>, TelemetryExportError> {
        let registry = Registry::new();

        let publish_total = Counter::with_opts(Opts::new(
            "pms_publish_total",
            "Total messages published across all PMS rings in this process",
        ))?;
        registry.register(Box::new(publish_total.clone()))?;

        let recv_latency_ns = Histogram::with_opts(
            HistogramOpts::new(
                "pms_recv_latency_ns",
                "Per-message wakeup latency (nanoseconds), wire-to-wire",
            )
            .buckets(vec![
                100.0,
                200.0,
                500.0,
                1_000.0,
                2_000.0,
                5_000.0,
                10_000.0,
                50_000.0,
                100_000.0,
                500_000.0,
                1_000_000.0,
            ]),
        )?;
        registry.register(Box::new(recv_latency_ns.clone()))?;

        let slot_occupancy = Gauge::with_opts(Opts::new(
            "pms_slot_occupancy",
            "Current write_cursor - read_cursor (in-flight slot count)",
        ))?;
        registry.register(Box::new(slot_occupancy.clone()))?;

        let conflation_compression_ratio = Gauge::with_opts(Opts::new(
            "pms_conflation_compression_ratio",
            "Conflation router: inbound msgs / delivered msgs (1.0 = no compression)",
        ))?;
        registry.register(Box::new(conflation_compression_ratio.clone()))?;

        let wait_strategy_mode = Gauge::with_opts(Opts::new(
            "pms_wait_strategy_mode",
            "Active wait strategy (0=busy-spin, 1=umwait, 2=park, 3=adaptive)",
        ))?;
        registry.register(Box::new(wait_strategy_mode.clone()))?;

        let prefetch_distance = Gauge::with_opts(Opts::new(
            "pms_prefetch_distance",
            "Current prefetch lookahead (slots; 0=disabled)",
        ))?;
        registry.register(Box::new(prefetch_distance.clone()))?;

        Ok(Arc::new(Self {
            registry,
            publish_total,
            recv_latency_ns,
            slot_occupancy,
            conflation_compression_ratio,
            wait_strategy_mode,
            prefetch_distance,
        }))
    }

    /// Render the metrics in Prometheus text format, suitable for scraping.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryExportError::Encode`] if the Prometheus
    /// text encoder fails to write the gathered metric families
    /// (structurally rare — typically only on out-of-memory or a
    /// custom collector that returns malformed metric data), or if
    /// the emitted bytes are not valid UTF-8.
    pub fn render(&self) -> Result<String, TelemetryExportError> {
        let metric_families = self.registry.gather();
        let encoder = TextEncoder::new();
        let mut buf = Vec::new();
        encoder
            .encode(&metric_families, &mut buf)
            .map_err(|e| TelemetryExportError::Encode(format!("{}", e)))?;
        String::from_utf8(buf).map_err(|e| TelemetryExportError::Encode(format!("{}", e)))
    }
}

// =============================================================================
// HTTP server pattern (production deployments typically embed render() in
// their existing telemetry collector instead of running a separate server)
// =============================================================================
//
// If you need a standalone /metrics endpoint, the canonical pattern is:
//
// ```ignore
// use axum::{routing::get, Router, response::IntoResponse};
// use std::sync::Arc;
//
// async fn metrics_handler(State(m): State<Arc<Metrics>>) -> impl IntoResponse {
//     match m.render() {
//         Ok(text) => (StatusCode::OK, text),
//         Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)),
//     }
// }
//
// let app = Router::new().route("/metrics", get(metrics_handler))
//     .with_state(Arc::clone(&metrics));
//
// let listener = tokio::net::TcpListener::bind("0.0.0.0:9090").await.unwrap();
// axum::serve(listener, app).await.unwrap();
// ```
//
// Adding axum + tokio as dependencies blows up our minimal-deps story for
// the bench harness (axum pulls in ~30 crates). Production wrappers should
// add this themselves.

#[cfg(test)]
// Test idiom: `.unwrap()` / `.expect()` / `panic!` / `assert!` are
// deliberate fail-fast in tests — a test that swallows its own
// setup failure reports false success. The workspace `[lints.clippy]`
// (root `Cargo.toml`) keeps these as `warn` for production code; the
// scoped `#[allow]` below ratifies the test-idiom exception, so
// production warnings are never silenced wholesale.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn metrics_construct_and_register() {
        let m = Metrics::new().expect("create");
        assert_eq!(m.publish_total.get(), 0.0);
        assert_eq!(m.slot_occupancy.get(), 0.0);
    }

    #[test]
    fn render_includes_all_metrics() {
        let m = Metrics::new().expect("create");
        m.publish_total.inc_by(42.0);
        m.slot_occupancy.set(1024.0);
        m.recv_latency_ns.observe(500.0);
        m.conflation_compression_ratio.set(11.0);
        m.wait_strategy_mode.set(0.0);
        m.prefetch_distance.set(1.0);

        let text = m.render().expect("render");
        assert!(text.contains("pms_publish_total 42"));
        assert!(text.contains("pms_slot_occupancy 1024"));
        assert!(text.contains("pms_recv_latency_ns_bucket"));
        assert!(text.contains("pms_conflation_compression_ratio 11"));
        assert!(text.contains("pms_wait_strategy_mode 0"));
        assert!(text.contains("pms_prefetch_distance 1"));
    }

    #[test]
    fn histogram_observes_and_buckets() {
        let m = Metrics::new().expect("create");
        for ns in [100, 250, 500, 1500, 7000] {
            m.recv_latency_ns.observe(ns as f64);
        }
        let text = m.render().expect("render");
        // Verify the histogram emitted bucket counts
        assert!(text.contains("pms_recv_latency_ns_count 5"));
        // Sum should be 100+250+500+1500+7000 = 9350
        assert!(text.contains("pms_recv_latency_ns_sum 9350"));
    }
}
