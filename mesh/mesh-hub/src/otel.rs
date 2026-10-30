// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The daemon's spans as OpenTelemetry traces, with the `otel` feature.
//!
//! The daemon makes its spans with `tracing` whether the feature is on or not:
//! `send`, `deliver`, `attach`, `detach`, `subscribe` and `unsubscribe`, at the
//! trace level, with the fields the crate's README lists. The binary keeps them
//! out of its log, so with nothing else installed each costs a level check and
//! records nothing.
//!
//! [`layer`] is what takes them: a `tracing-opentelemetry` layer that turns the
//! daemon's spans, and the warnings and errors logged inside them, into
//! OpenTelemetry spans for a tracer provider. [`Traces::from_env`] makes the
//! provider the binary uses when the environment names an OTLP collector
//! ([`traces_endpoint`]): it batches the spans on the Tokio runtime and posts
//! them as protobuf over HTTP, and [`Traces::shutdown`] exports what is left as
//! the daemon exits. A host embedding the daemon can put [`layer`] over a
//! provider of its own instead.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{InstrumentationScope, Key, KeyValue};
use opentelemetry_otlp::{
    ExporterBuildError, Protocol, SpanExporter, WithExportConfig as _, OTEL_EXPORTER_OTLP_ENDPOINT,
    OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
};
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::resource::{EnvResourceDetector, ResourceDetector as _};
use opentelemetry_sdk::runtime;
use opentelemetry_sdk::trace::span_processor_with_async_runtime::BatchSpanProcessor;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::filter::{filter_fn, LevelFilter};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// The service the traces name, `service.name`, unless `OTEL_SERVICE_NAME` or
/// a `service.name` in `OTEL_RESOURCE_ATTRIBUTES` names another; also the
/// instrumentation scope of every span.
pub const SERVICE_NAME: &str = "mesh-hub";

/// The resource attribute that carries the daemon's hub name.
pub const HUB_NAME_ATTRIBUTE: &str = "pulse_mesh.hub.name";

/// The target every span and event of the daemon's crates starts with, which
/// is what [`layer`] takes.
const DAEMON_TARGET: &str = "mesh_hub";

/// Where [`Traces::from_env`] sends the spans, read from the environment as
/// the OTLP exporter reads it: `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` as it is,
/// or else `OTEL_EXPORTER_OTLP_ENDPOINT` with `/v1/traces` after it. `None`
/// when neither is set to anything, and the daemon exports nothing.
#[must_use]
pub fn traces_endpoint() -> Option<String> {
    if let Some(url) = env_value(OTEL_EXPORTER_OTLP_TRACES_ENDPOINT) {
        return Some(url);
    }
    let base = env_value(OTEL_EXPORTER_OTLP_ENDPOINT)?;
    Some(format!(
        "{}/v1/traces",
        base.strip_suffix('/').unwrap_or(&base)
    ))
}

/// A variable's value when it is set to something; a value that is not
/// Unicode is shown with replacement characters, and the exporter refuses it.
fn env_value(name: &str) -> Option<String> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string_lossy().into_owned())
}

/// The resource the daemon's traces carry: what the SDK reads from the
/// environment (`OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`), the service
/// name [`SERVICE_NAME`] when the environment names none, and the hub name as
/// [`HUB_NAME_ATTRIBUTE`].
#[must_use]
pub fn resource(hub_name: &str) -> Resource {
    let mut builder = Resource::builder();
    if !service_named_by_env() {
        builder = builder.with_service_name(SERVICE_NAME);
    }
    builder
        .with_attribute(KeyValue::new(HUB_NAME_ATTRIBUTE, hub_name.to_string()))
        .build()
}

/// Whether `OTEL_SERVICE_NAME`, or a `service.name` in
/// `OTEL_RESOURCE_ATTRIBUTES`, names the service.
fn service_named_by_env() -> bool {
    env_value("OTEL_SERVICE_NAME").is_some()
        || EnvResourceDetector::new()
            .detect()
            .get(&Key::from_static_str("service.name"))
            .is_some()
}

/// The layer that turns the daemon's spans into OpenTelemetry spans for
/// `provider`, under the instrumentation scope [`SERVICE_NAME`] at the crate's
/// version. It takes the spans of the daemon's crates, and their warnings and
/// errors, which become events on the span they happen in (an error marks the
/// span's status too); it takes nothing else, so the log's debug and info lines
/// stay out of the traces.
pub fn layer<S>(provider: &SdkTracerProvider) -> impl Layer<S> + Send + Sync + 'static
where
    S: Subscriber + for<'span> LookupSpan<'span> + Send + Sync + 'static,
{
    let scope = InstrumentationScope::builder(SERVICE_NAME)
        .with_version(env!("CARGO_PKG_VERSION"))
        .build();
    tracing_opentelemetry::layer()
        .with_tracer(provider.tracer_with_scope(scope))
        .with_filter(filter_fn(is_daemon_span_or_warning).with_max_level_hint(LevelFilter::TRACE))
}

/// What [`layer`] takes: a span of the daemon's crates, or a warning or an
/// error they log.
fn is_daemon_span_or_warning(metadata: &Metadata<'_>) -> bool {
    metadata.target().starts_with(DAEMON_TARGET)
        && (metadata.is_span() || *metadata.level() <= Level::WARN)
}

/// A tracer provider exporting the daemon's spans to an OTLP collector over
/// HTTP, made by [`Traces::from_env`].
///
/// Spans are batched on the Tokio runtime and posted as protobuf to
/// [`Traces::endpoint`], over HTTP/1.1 without TLS: an `https` endpoint is
/// refused at each export, and a collector on the host, or one reached through
/// a local agent, is the way to a remote one. The exporter reads the rest of
/// its configuration from the standard variables (`OTEL_EXPORTER_OTLP_HEADERS`,
/// `OTEL_EXPORTER_OTLP_TIMEOUT`, `OTEL_BSP_*`, `OTEL_TRACES_SAMPLER`).
#[derive(Debug)]
pub struct Traces {
    provider: SdkTracerProvider,
    endpoint: String,
}

impl Traces {
    /// A provider for the hub `hub_name` exporting to the collector the
    /// environment names ([`traces_endpoint`]), with [`resource`]'s attributes;
    /// `None` when it names none. It must be called on a Tokio runtime, which
    /// runs the batching task, and that runtime must outlive
    /// [`Traces::shutdown`].
    ///
    /// # Errors
    ///
    /// The exporter's [`ExporterBuildError`] when the environment's endpoint,
    /// headers or timeout cannot be used.
    pub fn from_env(hub_name: &str) -> Result<Option<Self>, ExporterBuildError> {
        let Some(endpoint) = traces_endpoint() else {
            return Ok(None);
        };
        let exporter = SpanExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .build()?;
        let provider = SdkTracerProvider::builder()
            .with_span_processor(BatchSpanProcessor::builder(exporter, runtime::Tokio).build())
            .with_resource(resource(hub_name))
            .build();
        Ok(Some(Self { provider, endpoint }))
    }

    /// Where the spans go.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// [`layer`] over this provider.
    pub fn layer<S>(&self) -> impl Layer<S> + Send + Sync + 'static
    where
        S: Subscriber + for<'span> LookupSpan<'span> + Send + Sync + 'static,
    {
        layer(&self.provider)
    }

    /// Export the spans still batched and stop exporting: spans that end
    /// afterwards are dropped. It blocks until the last export ends, which the
    /// exporter's timeout bounds, so it must not be called on a thread the
    /// runtime runs its tasks on.
    ///
    /// # Errors
    ///
    /// The SDK's error when the last export failed or did not end in time.
    pub fn shutdown(self) -> OTelSdkResult {
        self.provider.shutdown()
    }
}
