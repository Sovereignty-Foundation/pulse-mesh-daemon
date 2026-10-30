# One domain's job, end to end

<p class="pm-kind"><b>Part opener</b> · for anyone putting Pulse Mesh to work in robotics, enterprise messaging, high-frequency trading or distributed compute</p>

A workflow has an example's shape and one domain's job: what you will have, one prompt for your agent, the same steps by hand with what each prints, checks, and what the code does and does not do yet. Where a workflow uses a ring from the profiles repository, it says which of the ring's parts are implemented and which are deferred.

- [The ring inside your process](/docs/workflows/ring-in-process.html): the shared-memory ring and the envelope store without the daemon, which is what the HFT ring builds on.
- [HFT: one feed, many readers, no copy per reader](/docs/profiles/workflows/hft-fanout.html): one writer, four readers and a ring in process memory, with the wait strategy chosen for the host and the path to several writers and NUMA placement.
- [Robotics: a 4 MiB scan through shared memory](/docs/profiles/workflows/robotics-large-payload.html): a scan in a shared-memory pool, a 16-byte reference in the Pulse, read and checked in another process, and the pool's limits seen.
- [Enterprise: Pulses between services over TLS 1.3](/docs/profiles/workflows/enterprise-tls.html): one frame across a verified TLS 1.3 handshake, and the stage's own statement of which modes are deferred.
- [Distributed compute: jobs across machines through linked daemons](distributed-compute.md): two daemons linked over sealed UDP, a job crossing from one to a subscriber of the other, and the path to the swarm across hosts, LAN discovery and a relay.
