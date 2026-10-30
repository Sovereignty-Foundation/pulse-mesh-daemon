// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
//! The hub's manifest matches the composition it declares and re-exports.

#[test]
fn manifest_lists_the_declared_composition() {
    let m = dev_hub::RING_MANIFEST;
    assert_eq!(
        m[0],
        (
            "functions",
            &["dev_functions::basket", "dev_functions::core_ops"][..]
        )
    );
    assert_eq!(m[1], ("stages", &["dev_stages::conflation"][..]));
}
