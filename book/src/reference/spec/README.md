<div class="pm-part">
  <span class="pm-monogram-large" aria-hidden="true">§</span>
  <span class="pm-eyebrow">Reference · The Pulse Mesh Standard</span>
  <h1>The <span class="pm-accent">specification</span></h1>
  <p class="pm-sub">The normative description of the Pulse, the PulseEnvelope, the ring, the store, the UDP transport and the port protocol, and what a conformant implementation must reproduce.</p>
</div>

<p class="pm-kind"><b>Reference · normative</b> · for anyone implementing, verifying or extending Pulse Mesh in any language</p>

This is the Pulse Mesh Standard as the reference implementation in this repository realises it. Where a chapter describes the reference implementation rather than a requirement on every implementation, it says so at the top.

**Status.** Working draft, lineage draft-00. Breaking changes between draft revisions are expected and are recorded, not hidden: a superseded rule stays in the text, marked as superseded, with the revision that replaced it. The conformance vectors under `pulse/pulse-spec/test-vectors` are the executable form of chapters 2 and 3; the chapter text and the vectors are checked against the code by the documentation gate and the workspace tests.

**How to read the requirement words.** MUST, MUST NOT, SHOULD, SHOULD NOT and MAY carry their usual normative meaning. A statement without one of those words is a description of the reference implementation, not a requirement on others.

| Chapter | Subject | Normative for |
|---|---|---|
| [1. Introduction](/docs/reference/spec/01-introduction.html) | Scope and terminology | Everyone |
| [2. The Pulse](/docs/reference/spec/02-pulse.html) | The 128-byte atom: layout, alignment, instructions, the heartbeat overlay | Every implementation |
| [3. The PulseEnvelope](/docs/reference/spec/03-envelope.html) | The canonical bytes, the content id, payload variants, recursion, self-verification | Every implementation |
| [4. The SeqLock ring](/docs/reference/spec/04-ring.html) | The shared-memory ring: header, slots, writer and reader protocol, crashed writers | Shared-memory substrates |
| [5. The envelope store](/docs/reference/spec/05-store.html) | The content-addressed store beside the ring: layout v2, claims that route around held slots, verified reads, lapping | The reference implementation |
| [6. The UDP transport](/docs/reference/spec/06-udp-transport.html) | Datagram framing, CRC, feedback, FEC, the capability handshake | The reference transport |
| [7. The Universal Port Protocol](07-port-protocol.md) | The daemon's JSON protocol over WebSocket and Unix socket, and its connection policy | Every client of the daemon |
| [8. Conformance](/docs/reference/spec/08-conformance.html) | What a conformant implementation reproduces, and what changes require a draft revision | Everyone |
| [Appendix A. BLAKE3](/docs/reference/spec/appendix-a-blake3.html) | The hash the content id is built on | Informative |
