// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The daemon's spans as OpenTelemetry traces, with the `otel` feature.
//!
//! 1. **The spans carry their fields**: a client's attach, subscribe, send,
//!    unsubscribe and detach through an embedded mesh, and the event written to
//!    it, are spans with the fields the README lists, under the daemon's
//!    instrumentation scope, on a resource naming the service and the hub.
//!
//! 2. **The binary exports them as it exits**: run with a collector named in
//!    its environment, it says in its log where the traces go and posts its
//!    spans there as OTLP protobuf over HTTP, the last of them while it exits
//!    on SIGTERM.
#![cfg(feature = "otel")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

mod common;

use common::{hub_name, socket_path, start_small, Upp};
use mesh_hub::embed::Bind;
use mesh_hub::otel::{HUB_NAME_ATTRIBUTE, SERVICE_NAME};
use opentelemetry::{Key, Value};
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};
use opentelemetry_sdk::Resource;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing_subscriber::layer::SubscriberExt as _;

const TIMEOUT: Duration = Duration::from_secs(5);

/// The spans a provider ends, and the resource it gives them, kept for the
/// test to read. The SDK's in-memory exporter needs its `testing` feature,
/// which a dev-dependency would build into every test run, the feature off
/// or on.
#[derive(Debug, Clone, Default)]
struct Collected {
    spans: Arc<Mutex<Vec<SpanData>>>,
    resource: Arc<Mutex<Option<Resource>>>,
}

impl SpanExporter for Collected {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        self.spans.lock().unwrap().extend(batch);
        Ok(())
    }

    fn set_resource(&mut self, resource: &Resource) {
        *self.resource.lock().unwrap() = Some(resource.clone());
    }
}

impl Collected {
    /// The spans ended so far once one of each name has, waiting up to
    /// [`TIMEOUT`]: an event's `deliver` ends after its client has it.
    fn wait_for(&self, names: &[&str]) -> Vec<SpanData> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let spans = self.spans.lock().unwrap().clone();
            if names
                .iter()
                .all(|name| spans.iter().any(|s| s.name == *name))
            {
                return spans;
            }
            assert!(
                Instant::now() < deadline,
                "spans ended: {:?}",
                spans.iter().map(|s| &s.name).collect::<Vec<_>>()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// The one span named `name`.
fn one<'a>(spans: &'a [SpanData], name: &str) -> &'a SpanData {
    let named: Vec<&SpanData> = spans.iter().filter(|s| s.name == name).collect();
    assert_eq!(named.len(), 1, "{name}: {named:#?}");
    named[0]
}

/// The attribute `key` of `span`, if it has one.
fn attribute(span: &SpanData, key: &str) -> Option<Value> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.clone())
}

fn text(value: &str) -> Option<Value> {
    Some(Value::from(value.to_string()))
}

fn number(value: usize) -> Option<Value> {
    Some(Value::I64(i64::try_from(value).unwrap()))
}

#[test]
fn a_clients_messages_through_an_embedded_mesh_are_spans_with_their_fields() {
    let hub = hub_name("otel");
    let collected = Collected::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(collected.clone())
        .with_resource(mesh_hub::otel::resource(&hub))
        .build();
    // Global, since the mesh's runtime threads make the spans.
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry().with(mesh_hub::otel::layer(&provider)),
    )
    .unwrap();

    let path = socket_path("otel");
    let mesh = start_small(&hub, &[Bind::Uds(path.clone())]).unwrap();
    let mut client = Upp::connect(&path);
    client.send(r#"{"op":"attach","id":"a","name":"tracer","protocol_version":"v0"}"#);
    let node = client.recv_json(TIMEOUT)["node_id"]
        .as_str()
        .unwrap()
        .to_string();
    client.send(r#"{"op":"subscribe","id":"s","filter":{"channel":"jobs"}}"#);
    let sub = client.recv_json(TIMEOUT)["subscription_id"]
        .as_str()
        .unwrap()
        .to_string();
    // Five payload bytes, "hello".
    client.send(r#"{"op":"send","id":"p","channel":"jobs","type_id":7,"payload":"aGVsbG8="}"#);
    let frames = [
        client.frame(TIMEOUT).unwrap(),
        client.frame(TIMEOUT).unwrap(),
    ];
    let event = frames
        .iter()
        .find(|f| f.starts_with(r#"{"op":"event""#))
        .expect("the event");
    client.send(&format!(
        r#"{{"op":"unsubscribe","id":"u","subscription_id":"{sub}"}}"#
    ));
    assert_eq!(client.recv_json(TIMEOUT)["events_dropped"], 0);
    client.send(r#"{"op":"detach","id":"d"}"#);
    assert_eq!(client.recv_json(TIMEOUT)["op"], "ack");

    let spans = collected.wait_for(&[
        "attach",
        "subscribe",
        "send",
        "deliver",
        "unsubscribe",
        "detach",
    ]);
    let send = one(&spans, "send");
    assert_eq!(attribute(send, "channel"), text("jobs"));
    assert_eq!(attribute(send, "type_id"), number(7));
    assert_eq!(attribute(send, "payload_bytes"), number(5));
    assert_eq!(attribute(send, "origin"), text(&node));
    assert_eq!(attribute(send, "matched"), number(1));
    assert_eq!(attribute(send, "persisted"), Some(Value::Bool(true)));
    let deliver = one(&spans, "deliver");
    assert_eq!(attribute(deliver, "subscription_id"), text(&sub));
    assert_eq!(attribute(deliver, "bytes"), number(event.len()));
    assert_eq!(attribute(one(&spans, "attach"), "name"), text("tracer"));
    assert_eq!(
        attribute(one(&spans, "subscribe"), "subscription_id"),
        text(&sub)
    );
    let unsubscribe = one(&spans, "unsubscribe");
    assert_eq!(attribute(unsubscribe, "subscription_id"), text(&sub));
    assert_eq!(attribute(unsubscribe, "events_dropped"), number(0));
    assert_eq!(attribute(one(&spans, "detach"), "name"), text("tracer"));
    for span in &spans {
        assert_eq!(span.instrumentation_scope.name(), SERVICE_NAME);
        assert_eq!(
            span.instrumentation_scope.version(),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    let resource = collected.resource.lock().unwrap().clone().unwrap();
    assert_eq!(
        resource.get(&Key::from_static_str(HUB_NAME_ATTRIBUTE)),
        Some(Value::from(hub.clone()))
    );
    // The default service name, unless this run's environment names another.
    if std::env::var_os("OTEL_SERVICE_NAME").is_none()
        && std::env::var_os("OTEL_RESOURCE_ATTRIBUTES").is_none()
    {
        assert_eq!(
            resource.get(&Key::from_static_str("service.name")),
            Some(Value::from(SERVICE_NAME))
        );
    }
    println!(
        "otel: {} spans from an embedded mesh, the send's six fields as sent",
        spans.len()
    );
    mesh.shutdown();
    provider.shutdown().unwrap();
}

/// One request a [`Collector`] received.
#[derive(Debug, Clone)]
struct Request {
    line: String,
    content_type: Option<String>,
    body: Vec<u8>,
}

/// An OTLP/HTTP collector that keeps what it is sent and answers each
/// request with an empty success.
struct Collector {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl Collector {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let kept = Arc::clone(&kept);
                std::thread::spawn(move || serve(stream, &kept));
            }
        });
        Self { addr, requests }
    }
}

/// Read requests from `stream` until it closes, keeping each before it is
/// answered, so that whoever reads the answer finds the request kept.
fn serve(stream: TcpStream, kept: &Mutex<Vec<Request>>) {
    stream.set_read_timeout(Some(TIMEOUT * 6)).unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let (mut length, mut content_type) = (0, None);
        loop {
            let mut header = String::new();
            reader.read_line(&mut header).unwrap();
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            let (name, value) = header.split_once(':').unwrap();
            match name.to_ascii_lowercase().as_str() {
                "content-length" => length = value.trim().parse().unwrap(),
                "content-type" => content_type = Some(value.trim().to_string()),
                _ => {}
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        kept.lock().unwrap().push(Request {
            line: line.trim_end().to_string(),
            content_type,
            body,
        });
        writer
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/x-protobuf\r\ncontent-length: 0\r\n\r\n")
            .unwrap();
    }
}

/// Whether `haystack` holds `needle`; the protobuf keeps strings as they are.
fn holds(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

#[test]
fn the_binary_exports_its_spans_to_the_collector_its_environment_names_as_it_exits() {
    let collector = Collector::start();
    let socket = socket_path("otel-bin");
    let log = socket.with_extension("log");
    let out = std::fs::File::create(&log).unwrap();
    let hub = hub_name("otelb");
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_mesh-hub"))
        .args(["--hub-name", &hub, "--uds-path"])
        .arg(&socket)
        .args(["--no-ws", "--store-slots", "4"])
        .env("MESH_HUB_LOG", "info")
        .env(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            format!("http://{}/", collector.addr),
        )
        .env("OTEL_SERVICE_NAME", "otel-test-daemon")
        // The batch timer never fires within the test, so only the flush as
        // the daemon exits can export.
        .env("OTEL_BSP_SCHEDULE_DELAY", "600000")
        .env_remove("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        .env_remove("OTEL_EXPORTER_OTLP_HEADERS")
        .env_remove("OTEL_RESOURCE_ATTRIBUTES")
        .env_remove("OTEL_TRACES_SAMPLER")
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .spawn()
        .expect("start mesh-hub");
    let read_log = || std::fs::read_to_string(&log).unwrap_or_default();

    let deadline = Instant::now() + Duration::from_secs(20);
    while UnixStream::connect(&socket).is_err() {
        if let Some(status) = daemon.try_wait().unwrap() {
            panic!("mesh-hub exited ({status}):\n{}", read_log());
        }
        assert!(
            Instant::now() < deadline,
            "mesh-hub never answered:\n{}",
            read_log()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut client = Upp::connect(&socket);
    client.attach("exporter");
    client.send(r#"{"op":"send","id":"p","channel":"otel-jobs","payload":"aGk="}"#);
    assert_eq!(client.recv_json(TIMEOUT)["op"], "ack");
    assert!(
        collector.requests.lock().unwrap().is_empty(),
        "nothing is exported before the exit"
    );

    let sent = Command::new("kill")
        .args(["-TERM", &daemon.id().to_string()])
        .status()
        .unwrap();
    assert!(sent.success());
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = daemon.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = daemon.kill();
            let _ = daemon.wait();
            panic!("mesh-hub did not exit on SIGTERM:\n{}", read_log());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let text = read_log();
    let _ = std::fs::remove_file(&log);
    assert!(status.success(), "{status}:\n{text}");
    let endpoint = format!("http://{}/v1/traces", collector.addr);
    assert!(
        text.contains("exporting traces over OTLP/HTTP") && text.contains(&endpoint),
        "the log:\n{text}"
    );

    let requests = collector.requests.lock().unwrap().clone();
    assert!(!requests.is_empty(), "nothing was exported:\n{text}");
    for request in &requests {
        assert_eq!(request.line, "POST /v1/traces HTTP/1.1");
        assert_eq!(
            request.content_type.as_deref(),
            Some("application/x-protobuf")
        );
    }
    let body: Vec<u8> = requests.iter().flat_map(|r| r.body.clone()).collect();
    for expected in [
        "send",
        "attach",
        "otel-jobs",
        "otel-test-daemon",
        HUB_NAME_ATTRIBUTE,
        &hub,
    ] {
        assert!(holds(&body, expected), "{expected} is not in what was sent");
    }
    println!(
        "otel: {} request(s) to {endpoint} as the daemon exited, {} bytes",
        requests.len(),
        body.len()
    );
}
