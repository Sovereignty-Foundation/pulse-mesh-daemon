// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The schema registry, tier 2: which nodes may produce and consume which envelope types.
//!
//! A runtime access-control layer: it validates an envelope's type and
//! payload against what is registered, and tracks each type's producers
//! and consumers. It is a sibling of the Lexicon™ (`mesh-lex`), the
//! published catalog external implementations verify against, and may be
//! stricter or looser than it: it governs one running mesh, not the
//! standard.
//!
//! A schema's producer and consumer lists hold node ids. A daemon's client
//! attached by name has the id its name hashes to
//! (`pulse_canon::NodeId::from_name`), which anyone may claim; one that
//! proved a key at attach has the id the key derives
//! (`NodeId::from_bytes(mesh_port_protocol::attach::key_node_id(&key))`), so
//! a list of those ids admits the holders of those keys alone.
//!
//! In the book: <https://pulse-mesh.net/docs/daemon/architecture/mesh.html>.
#![forbid(unsafe_code)]

use pulse_canon::{NodeId, PulseEnvelope};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

/// How to validate an envelope payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ValidationMode {
    /// No payload check.
    #[default]
    None,
    /// The payload's length is within bounds.
    Length {
        /// Minimum acceptable payload length in bytes (inclusive).
        min: usize,
        /// Maximum acceptable payload length in bytes (inclusive).
        max: usize,
    },
    /// The payload is valid JSON.
    Json,
    /// The caller's own check: the [`CustomValidator`] registered for the
    /// schema's type with [`SchemaRegistry::register_validator`] decides. A
    /// schema of this mode with no validator registered refuses every
    /// envelope, so a check that was meant and never installed admits
    /// nothing.
    Custom,
}

/// A payload check of the caller's, which [`SchemaRegistry::validate`] runs
/// for a schema whose mode is [`ValidationMode::Custom`], after the producer
/// list has admitted the envelope's origin: it is given the envelope and the
/// origin's node id, and its error refuses the envelope.
pub type CustomValidator =
    Arc<dyn Fn(&PulseEnvelope, &NodeId) -> Result<(), SchemaError> + Send + Sync>;

/// A registered envelope schema.
#[derive(Debug, Clone)]
pub struct SchemaEntry {
    /// Unique type identifier.
    pub type_id: u16,
    /// Human-readable name (e.g., "canon_vector").
    pub name: String,
    /// Schema version for compatibility.
    pub version: u32,
    /// How to validate payloads of this type.
    pub validation: ValidationMode,
    /// Nodes that may produce this type; empty admits every node.
    pub producers: HashSet<NodeId>,
    /// Nodes that may consume this type; empty admits every node.
    pub consumers: HashSet<NodeId>,
}

impl SchemaEntry {
    /// A schema entry at version 1, with no payload check and open ACLs.
    pub fn new(type_id: u16, name: impl Into<String>) -> Self {
        Self {
            type_id,
            name: name.into(),
            version: 1,
            validation: ValidationMode::None,
            producers: HashSet::new(),
            consumers: HashSet::new(),
        }
    }

    /// Set the schema version; bump it on a breaking change.
    pub fn with_version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Set the payload check.
    pub fn with_validation(mut self, validation: ValidationMode) -> Self {
        self.validation = validation;
        self
    }

    /// Add a node to [`Self::producers`].
    pub fn add_producer(mut self, node: NodeId) -> Self {
        self.producers.insert(node);
        self
    }

    /// Add a node to [`Self::consumers`].
    pub fn add_consumer(mut self, node: NodeId) -> Self {
        self.consumers.insert(node);
        self
    }

    /// Check if a node can produce this envelope type.
    pub fn can_produce(&self, node: &NodeId) -> bool {
        self.producers.is_empty() || self.producers.contains(node)
    }

    /// Check if a node can consume this envelope type.
    pub fn can_consume(&self, node: &NodeId) -> bool {
        self.consumers.is_empty() || self.consumers.contains(node)
    }
}

/// Registry of envelope schemas known to the Hub.
#[derive(Default)]
pub struct SchemaRegistry {
    schemas: HashMap<u16, SchemaEntry>,
    by_name: HashMap<String, u16>,
    /// The checks of the [`ValidationMode::Custom`] schemas, by type id.
    validators: HashMap<u16, CustomValidator>,
}

impl fmt::Debug for SchemaRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut validated: Vec<&u16> = self.validators.keys().collect();
        validated.sort_unstable();
        f.debug_struct("SchemaRegistry")
            .field("schemas", &self.schemas)
            .field("by_name", &self.by_name)
            .field("validators", &validated)
            .finish()
    }
}

/// Errors raised by [`SchemaRegistry`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SchemaError {
    /// A schema with this `type_id` is already registered.
    TypeIdExists(u16),
    /// A schema with this name is already registered.
    NameExists(String),
    /// No schema is registered under this `type_id`.
    UnknownType(u16),
    /// The producing node is not on the schema's producer ACL.
    ProducerNotAllowed(NodeId),
    /// The payload failed the schema's [`ValidationMode`]; carries the reason.
    ValidationFailed(String),
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TypeIdExists(id) => write!(f, "type id {} already registered", id),
            Self::NameExists(name) => write!(f, "schema name '{}' already registered", name),
            Self::UnknownType(id) => write!(f, "unknown envelope type {}", id),
            Self::ProducerNotAllowed(node) => write!(f, "node {} not allowed to produce", node),
            Self::ValidationFailed(msg) => write!(f, "validation failed: {}", msg),
        }
    }
}

impl std::error::Error for SchemaError {}

impl SchemaRegistry {
    /// Build an empty registry. Equivalent to [`Default::default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a schema; type ids and names are each unique.
    ///
    /// # Errors
    ///
    /// [`SchemaError::TypeIdExists`] or [`SchemaError::NameExists`] on a
    /// collision, which leaves the registry unchanged.
    pub fn register(&mut self, entry: SchemaEntry) -> Result<(), SchemaError> {
        if self.schemas.contains_key(&entry.type_id) {
            return Err(SchemaError::TypeIdExists(entry.type_id));
        }
        if self.by_name.contains_key(&entry.name) {
            return Err(SchemaError::NameExists(entry.name.clone()));
        }

        self.by_name.insert(entry.name.clone(), entry.type_id);
        self.schemas.insert(entry.type_id, entry);
        Ok(())
    }

    /// Get a schema by type ID.
    pub fn get(&self, type_id: u16) -> Option<&SchemaEntry> {
        self.schemas.get(&type_id)
    }

    /// Get a schema by name.
    pub fn get_by_name(&self, name: &str) -> Option<&SchemaEntry> {
        self.by_name.get(name).and_then(|id| self.schemas.get(id))
    }

    /// Check if a type is registered.
    pub fn contains(&self, type_id: u16) -> bool {
        self.schemas.contains_key(&type_id)
    }

    /// Validate an envelope from `origin` against the schema registered for
    /// its numeric type. A type name routes an envelope whose type is 0 or
    /// has no schema, and such an envelope passes unchecked; an envelope of a
    /// registered type other than 0 is checked, named or not.
    ///
    /// # Errors
    ///
    /// [`SchemaError::UnknownType`] if the envelope has no type name and no
    /// schema has its type;
    /// [`SchemaError::ProducerNotAllowed`] if `origin` may not produce it;
    /// [`SchemaError::ValidationFailed`] if the payload fails the schema's
    /// [`ValidationMode`], or the schema's mode is [`ValidationMode::Custom`]
    /// and no validator is registered for it; for a custom schema, whatever
    /// its [`CustomValidator`] returns.
    pub fn validate(&self, envelope: &PulseEnvelope, origin: &NodeId) -> Result<(), SchemaError> {
        let named = envelope.type_name().is_some();
        if named && envelope.envelope_type() == 0 {
            return Ok(());
        }
        let Some(schema) = self.schemas.get(&envelope.envelope_type()) else {
            return if named {
                Ok(())
            } else {
                Err(SchemaError::UnknownType(envelope.envelope_type()))
            };
        };

        if !schema.can_produce(origin) {
            return Err(SchemaError::ProducerNotAllowed(*origin));
        }

        let payload_bytes = envelope.payload().to_bytes();
        match &schema.validation {
            ValidationMode::None => Ok(()),
            ValidationMode::Length { min, max } => {
                let len = payload_bytes.len();
                if len < *min || len > *max {
                    Err(SchemaError::ValidationFailed(format!(
                        "payload length {} not in range [{}, {}]",
                        len, min, max
                    )))
                } else {
                    Ok(())
                }
            }
            ValidationMode::Json => serde_json::from_slice::<serde_json::Value>(&payload_bytes)
                .map(|_| ())
                .map_err(|e| SchemaError::ValidationFailed(e.to_string())),
            ValidationMode::Custom => match self.validators.get(&schema.type_id) {
                Some(validator) => validator(envelope, origin),
                None => Err(SchemaError::ValidationFailed(format!(
                    "schema {} ({:#06x}) is custom, and no validator is registered for it",
                    schema.name, schema.type_id
                ))),
            },
        }
    }

    /// Register `validator` as the check of the schema of `type_id`, which
    /// [`Self::validate`] runs while that schema's mode is
    /// [`ValidationMode::Custom`]; it replaces the one registered before.
    ///
    /// # Errors
    ///
    /// [`SchemaError::UnknownType`] if `type_id` is not registered, with
    /// nothing registered.
    pub fn register_validator<F>(&mut self, type_id: u16, validator: F) -> Result<(), SchemaError>
    where
        F: Fn(&PulseEnvelope, &NodeId) -> Result<(), SchemaError> + Send + Sync + 'static,
    {
        if !self.schemas.contains_key(&type_id) {
            return Err(SchemaError::UnknownType(type_id));
        }
        self.validators.insert(type_id, Arc::new(validator));
        Ok(())
    }

    /// Add a producer to a registered schema.
    ///
    /// # Errors
    ///
    /// [`SchemaError::UnknownType`] if `type_id` is not registered.
    pub fn add_producer(&mut self, type_id: u16, node: NodeId) -> Result<(), SchemaError> {
        let schema = self
            .schemas
            .get_mut(&type_id)
            .ok_or(SchemaError::UnknownType(type_id))?;
        schema.producers.insert(node);
        Ok(())
    }

    /// Add a consumer to a registered schema.
    ///
    /// # Errors
    ///
    /// [`SchemaError::UnknownType`] if `type_id` is not registered.
    pub fn add_consumer(&mut self, type_id: u16, node: NodeId) -> Result<(), SchemaError> {
        let schema = self
            .schemas
            .get_mut(&type_id)
            .ok_or(SchemaError::UnknownType(type_id))?;
        schema.consumers.insert(node);
        Ok(())
    }

    /// Get all nodes that can consume a given type.
    pub fn consumers_of(&self, type_id: u16) -> Option<&HashSet<NodeId>> {
        self.schemas.get(&type_id).map(|s| &s.consumers)
    }

    /// Number of registered schemas.
    pub fn len(&self) -> usize {
        self.schemas.len()
    }

    /// `true` when no schemas are registered.
    pub fn is_empty(&self) -> bool {
        self.schemas.is_empty()
    }

    /// Iterator over all schemas.
    pub fn iter(&self) -> impl Iterator<Item = &SchemaEntry> {
        self.schemas.values()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use pulse_canon::PulseEnvelope;

    #[test]
    fn register_and_get() {
        let mut registry = SchemaRegistry::new();
        let entry = SchemaEntry::new(0x0010, "canon_vector");
        registry.register(entry).unwrap();

        assert!(registry.contains(0x0010));
        assert_eq!(registry.get(0x0010).unwrap().name, "canon_vector");
        assert_eq!(
            registry.get_by_name("canon_vector").unwrap().type_id,
            0x0010
        );
    }

    #[test]
    fn reject_duplicate_type_id() {
        let mut registry = SchemaRegistry::new();
        registry
            .register(SchemaEntry::new(0x0010, "first"))
            .unwrap();
        let result = registry.register(SchemaEntry::new(0x0010, "second"));
        assert!(matches!(result, Err(SchemaError::TypeIdExists(0x0010))));
    }

    #[test]
    fn reject_duplicate_name() {
        let mut registry = SchemaRegistry::new();
        registry.register(SchemaEntry::new(0x0010, "same")).unwrap();
        let result = registry.register(SchemaEntry::new(0x0011, "same"));
        assert!(matches!(result, Err(SchemaError::NameExists(_))));
    }

    #[test]
    fn validate_unknown_type() {
        let registry = SchemaRegistry::new();
        let env = PulseEnvelope::new(0x9999, vec![]);
        let origin = NodeId::from_name("test");
        let result = registry.validate(&env, &origin);
        assert!(matches!(result, Err(SchemaError::UnknownType(0x9999))));
    }

    #[test]
    fn typed_envelope_bypasses_schema() {
        let registry = SchemaRegistry::new();
        let env = PulseEnvelope::typed("test/tool_call", vec![1, 2, 3]);
        let origin = NodeId::from_name("agent-guard");
        assert!(registry.validate(&env, &origin).is_ok());
    }

    /// A daemon send carries the client's type id beside a name; no schema
    /// governs that type, so the name routes it.
    #[test]
    fn named_envelope_of_an_unregistered_type_passes() {
        let registry = SchemaRegistry::new();
        let env = PulseEnvelope::with_content(0x0042, Some("app/job".into()), vec![1]);
        assert!(registry.validate(&env, &NodeId::from_name("o")).is_ok());
    }

    /// A name does not exempt an envelope from the schema of its type.
    #[test]
    fn named_envelope_of_a_registered_type_is_checked() {
        let mut registry = SchemaRegistry::new();
        let entry = SchemaEntry::new(0x0010, "sized")
            .with_validation(ValidationMode::Length { min: 10, max: 100 });
        registry.register(entry).unwrap();
        let env = PulseEnvelope::with_content(0x0010, Some("app/sized".into()), vec![0; 5]);
        assert!(matches!(
            registry.validate(&env, &NodeId::from_name("o")),
            Err(SchemaError::ValidationFailed(_))
        ));
    }

    #[test]
    fn validate_producer_check() {
        let mut registry = SchemaRegistry::new();
        let producer = NodeId::from_name("allowed");
        let other = NodeId::from_name("other");

        let entry = SchemaEntry::new(0x0010, "restricted").add_producer(producer);
        registry.register(entry).unwrap();

        let env = PulseEnvelope::new(0x0010, vec![]);
        assert!(registry.validate(&env, &producer).is_ok());
        assert!(matches!(
            registry.validate(&env, &other),
            Err(SchemaError::ProducerNotAllowed(_))
        ));
    }

    #[test]
    fn validate_length() {
        let mut registry = SchemaRegistry::new();
        let entry = SchemaEntry::new(0x0010, "sized")
            .with_validation(ValidationMode::Length { min: 10, max: 100 });
        registry.register(entry).unwrap();

        let origin = NodeId::from_name("test");

        let too_short = PulseEnvelope::new(0x0010, vec![0; 5]);
        assert!(matches!(
            registry.validate(&too_short, &origin),
            Err(SchemaError::ValidationFailed(_))
        ));

        let too_long = PulseEnvelope::new(0x0010, vec![0; 200]);
        assert!(matches!(
            registry.validate(&too_long, &origin),
            Err(SchemaError::ValidationFailed(_))
        ));

        let just_right = PulseEnvelope::new(0x0010, vec![0; 50]);
        assert!(registry.validate(&just_right, &origin).is_ok());
    }

    #[test]
    fn validate_json() {
        let mut registry = SchemaRegistry::new();
        let entry = SchemaEntry::new(0x0001, "json").with_validation(ValidationMode::Json);
        registry.register(entry).unwrap();

        let origin = NodeId::from_name("test");

        let valid = PulseEnvelope::new(0x0001, br#"{"key": "value"}"#.to_vec());
        assert!(registry.validate(&valid, &origin).is_ok());

        let invalid = PulseEnvelope::new(0x0001, b"not json".to_vec());
        assert!(matches!(
            registry.validate(&invalid, &origin),
            Err(SchemaError::ValidationFailed(_))
        ));
    }

    #[test]
    fn empty_producers_allows_all() {
        let entry = SchemaEntry::new(0x0010, "open");
        let any_node = NodeId::from_name("anyone");
        assert!(entry.can_produce(&any_node));
    }

    #[test]
    fn add_producer_to_existing() {
        let mut registry = SchemaRegistry::new();
        registry.register(SchemaEntry::new(0x0010, "test")).unwrap();

        let node = NodeId::from_name("new_producer");
        registry.add_producer(0x0010, node).unwrap();

        let schema = registry.get(0x0010).unwrap();
        assert!(schema.producers.contains(&node));
    }

    #[test]
    fn empty_registry() {
        let registry = SchemaRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.get(0x0010).is_none());
        assert!(registry.get_by_name("anything").is_none());
        assert!(!registry.contains(0x0010));
    }

    #[test]
    fn add_consumer_to_existing() {
        let mut registry = SchemaRegistry::new();
        registry.register(SchemaEntry::new(0x0010, "test")).unwrap();

        let node = NodeId::from_name("consumer");
        registry.add_consumer(0x0010, node).unwrap();

        let schema = registry.get(0x0010).unwrap();
        assert!(schema.consumers.contains(&node));
    }

    #[test]
    fn add_producer_unknown_type() {
        let mut registry = SchemaRegistry::new();
        let result = registry.add_producer(0x9999, NodeId::from_name("x"));
        assert!(matches!(result, Err(SchemaError::UnknownType(0x9999))));
    }

    #[test]
    fn add_consumer_unknown_type() {
        let mut registry = SchemaRegistry::new();
        let result = registry.add_consumer(0x9999, NodeId::from_name("x"));
        assert!(matches!(result, Err(SchemaError::UnknownType(0x9999))));
    }

    #[test]
    fn consumers_of() {
        let mut registry = SchemaRegistry::new();
        registry.register(SchemaEntry::new(0x0010, "test")).unwrap();

        let c1 = NodeId::from_name("c1");
        let c2 = NodeId::from_name("c2");
        registry.add_consumer(0x0010, c1).unwrap();
        registry.add_consumer(0x0010, c2).unwrap();

        let consumers = registry.consumers_of(0x0010).unwrap();
        assert!(consumers.contains(&c1));
        assert!(consumers.contains(&c2));
        assert_eq!(consumers.len(), 2);

        assert!(registry.consumers_of(0x9999).is_none());
    }

    #[test]
    fn schema_iter() {
        let mut registry = SchemaRegistry::new();
        registry.register(SchemaEntry::new(0x0001, "a")).unwrap();
        registry.register(SchemaEntry::new(0x0002, "b")).unwrap();
        registry.register(SchemaEntry::new(0x0003, "c")).unwrap();

        let names: Vec<&str> = registry.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        assert!(names.contains(&"c"));
    }

    #[test]
    fn schema_entry_with_version() {
        let entry = SchemaEntry::new(0x0010, "versioned").with_version(5);
        assert_eq!(entry.version, 5);
    }

    #[test]
    fn empty_consumers_allows_all() {
        let entry = SchemaEntry::new(0x0010, "open");
        let any_node = NodeId::from_name("anyone");
        assert!(entry.can_consume(&any_node));
    }

    #[test]
    fn restricted_consumer_rejects_unknown() {
        let consumer = NodeId::from_name("allowed");
        let entry = SchemaEntry::new(0x0010, "restricted").add_consumer(consumer);

        assert!(entry.can_consume(&consumer));
        assert!(!entry.can_consume(&NodeId::from_name("other")));
    }

    #[test]
    fn schema_error_display() {
        assert!(format!("{}", SchemaError::TypeIdExists(42)).contains("42"));
        assert!(format!("{}", SchemaError::NameExists("foo".into())).contains("foo"));
        assert!(format!("{}", SchemaError::UnknownType(99)).contains("99"));
        assert!(format!(
            "{}",
            SchemaError::ProducerNotAllowed(NodeId::from_name("x"))
        )
        .contains("not allowed"));
        assert!(format!("{}", SchemaError::ValidationFailed("bad".into())).contains("bad"));
    }

    /// A custom schema runs its validator, after the producer list, with
    /// the envelope and the origin; the validator can refuse. Without one, a
    /// custom schema refuses everything.
    #[test]
    fn a_custom_schema_runs_its_validator_and_refuses_without_one() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let mut registry = SchemaRegistry::new();
        let entry = SchemaEntry::new(0x0010, "custom").with_validation(ValidationMode::Custom);
        registry.register(entry).unwrap();
        let origin = NodeId::from_name("test");
        let env = PulseEnvelope::new(0x0010, b"anything".to_vec());
        assert!(
            matches!(
                registry.validate(&env, &origin),
                Err(SchemaError::ValidationFailed(why)) if why.contains("no validator")
            ),
            "a custom schema without a validator admits nothing"
        );

        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        registry
            .register_validator(0x0010, move |envelope, node| {
                seen.fetch_add(1, Ordering::Relaxed);
                assert_eq!(*node, NodeId::from_name("test"));
                if envelope.payload().to_bytes().starts_with(b"ok") {
                    Ok(())
                } else {
                    Err(SchemaError::ValidationFailed("not ok".into()))
                }
            })
            .unwrap();
        let ok = PulseEnvelope::new(0x0010, b"ok then".to_vec());
        assert_eq!(registry.validate(&ok, &origin), Ok(()));
        assert_eq!(
            registry.validate(&env, &origin),
            Err(SchemaError::ValidationFailed("not ok".into()))
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert!(format!("{registry:?}").contains("validators: [16]"));

        // A validator for a type nobody registered is refused.
        assert!(matches!(
            registry.register_validator(0x0011, |_, _| Ok(())),
            Err(SchemaError::UnknownType(0x0011))
        ));
        // A schema of another mode does not run it.
        let mut other = SchemaRegistry::new();
        other.register(SchemaEntry::new(0x0012, "plain")).unwrap();
        other
            .register_validator(0x0012, |_, _| {
                Err(SchemaError::ValidationFailed("never run".into()))
            })
            .unwrap();
        assert_eq!(
            other.validate(&PulseEnvelope::new(0x0012, vec![]), &origin),
            Ok(())
        );
    }

    /// The producer list runs before the validator: a node not on it is
    /// refused without the validator being asked.
    #[test]
    fn the_producer_list_is_checked_before_the_custom_validator() {
        let mut registry = SchemaRegistry::new();
        let allowed = NodeId::from_name("allowed");
        registry
            .register(
                SchemaEntry::new(0x0010, "custom")
                    .with_validation(ValidationMode::Custom)
                    .add_producer(allowed),
            )
            .unwrap();
        registry
            .register_validator(0x0010, |_, _| panic!("asked for a node the list refuses"))
            .unwrap();
        let env = PulseEnvelope::new(0x0010, vec![]);
        assert!(matches!(
            registry.validate(&env, &NodeId::from_name("other")),
            Err(SchemaError::ProducerNotAllowed(_))
        ));
    }

    /// A producer list naming a key, by the node id the key derives, admits
    /// the sends of a client that proved that key and refuses another key's,
    /// and any name's, the key's own bytes taken as a name included.
    #[test]
    fn a_producer_list_naming_a_key_admits_that_key_alone() {
        use mesh_port_protocol::attach::{key_node_id, SigningKey};
        let key = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
        let other = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
        let node = |key: &[u8; 32]| NodeId::from_bytes(key_node_id(key));
        let mut registry = SchemaRegistry::new();
        registry
            .register(SchemaEntry::new(0x0010, "keyed").add_producer(node(&key)))
            .unwrap();
        let env = PulseEnvelope::new(0x0010, b"x".to_vec());
        assert_eq!(registry.validate(&env, &node(&key)), Ok(()));
        assert!(matches!(
            registry.validate(&env, &node(&other)),
            Err(SchemaError::ProducerNotAllowed(_))
        ));
        let as_name = String::from_utf8_lossy(&key).into_owned();
        assert!(matches!(
            registry.validate(&env, &NodeId::from_name(&as_name)),
            Err(SchemaError::ProducerNotAllowed(_))
        ));
        assert!(registry.consumers_of(0x0010).unwrap().is_empty());
        let schema = registry.get(0x0010).unwrap();
        assert!(schema.can_produce(&node(&key)) && !schema.can_produce(&node(&other)));
    }

    #[test]
    fn validate_length_boundary_values() {
        let mut registry = SchemaRegistry::new();
        let entry = SchemaEntry::new(0x0010, "bounded")
            .with_validation(ValidationMode::Length { min: 5, max: 10 });
        registry.register(entry).unwrap();

        let origin = NodeId::from_name("test");

        let at_min = PulseEnvelope::new(0x0010, vec![0; 5]);
        assert!(registry.validate(&at_min, &origin).is_ok());

        let at_max = PulseEnvelope::new(0x0010, vec![0; 10]);
        assert!(registry.validate(&at_max, &origin).is_ok());

        let below_min = PulseEnvelope::new(0x0010, vec![0; 4]);
        assert!(registry.validate(&below_min, &origin).is_err());

        let above_max = PulseEnvelope::new(0x0010, vec![0; 11]);
        assert!(registry.validate(&above_max, &origin).is_err());
    }
}
