// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 Sovereignty Foundation
// Multi-language template — Node subscriber.
//
// Pairs with python_publisher.py. Both processes attach to the same
// mesh-hub daemon and exchange envelopes through the v0 Universal Port
// Protocol.

'use strict';

const path = require('path');
// Resolve the thin client from the sibling directory (no install required).
const { attach } = require(path.resolve(
  __dirname,
  '../../clients/pms-node-thin/index.js',
));

(async () => {
  const mesh = await attach('node-subscriber');
  console.log('node: attached; listening on multi-lang/demo (Ctrl-C to stop)');
  await mesh.on('multi-lang/demo', (ev) => {
    const text = ev.payload.toString('utf8');
    console.log(`node: got '${text}' (envelope ${ev.envelopeId.slice(0, 8)})`);
  });
  await mesh.run();
})();
