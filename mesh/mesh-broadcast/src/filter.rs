// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! [`ListenFilter`], the predicate that matches envelopes to listeners.

use pulse_canon::Instruction;
use pulse_canon::NodeId;
use pulse_canon::PulseEnvelope;

/// A predicate that decides whether a given envelope matches a listener.
#[derive(Debug, Clone)]
pub enum ListenFilter {
    /// Match every envelope.
    All,

    /// Match envelopes whose numeric `envelope_type` is exactly this value.
    Type(u16),

    /// Match envelopes whose `type_name` is exactly this string.
    TypeName(String),

    /// Match envelopes whose `type_name` starts with this prefix.
    TypePrefix(String),

    /// Match envelopes whose associated Pulse carries this `Instruction`.
    Instruction(Instruction),

    /// Match envelopes whose `origin` equals this node identifier.
    Origin(NodeId),

    /// Match envelopes whose associated Pulse declares this scope.
    Scope(u32),

    /// Logical AND of sub-filters. Empty `And` is vacuously true.
    And(Vec<ListenFilter>),

    /// Logical OR of sub-filters. Empty `Or` is false.
    Or(Vec<ListenFilter>),
}

impl ListenFilter {
    /// Whether `envelope` matches, given the `instruction` and `scope` of the
    /// Pulse that referenced it (`None` without one). Pure: the result
    /// depends on the arguments alone.
    pub fn matches(
        &self,
        envelope: &PulseEnvelope,
        instruction: Option<Instruction>,
        scope: Option<u32>,
    ) -> bool {
        match self {
            Self::All => true,
            Self::Type(t) => envelope.envelope_type() == *t,
            Self::TypeName(name) => envelope.type_name() == Some(name.as_str()),
            Self::TypePrefix(prefix) => envelope
                .type_name()
                .map(|n| n.starts_with(prefix.as_str()))
                .unwrap_or(false),
            Self::Instruction(code) => instruction == Some(*code),
            Self::Origin(node) => envelope.origin == node.0,
            Self::Scope(s) => scope == Some(*s),
            Self::And(filters) => filters
                .iter()
                .all(|f| f.matches(envelope, instruction, scope)),
            Self::Or(filters) => filters
                .iter()
                .any(|f| f.matches(envelope, instruction, scope)),
        }
    }
}
