# capture-agent

The ingestion boundary of the GUARDIAN pipeline: receives telemetry events over
`POST /ingest` and produces them to Redpanda topic `guardian.telemetry.raw`.

**This is the MVP stand-in for real eBPF traffic mirroring.** Kernel-level eBPF
(Cilium Tetragon) needs a native Linux kernel; inside Docker Desktop's WSL2/Hyper-V VM
on the dev laptops, promiscuous-mode capture of other containers' traffic is unreliable.
The agent therefore sits at the same architectural seam a mirror agent would (between
telemetry source and queue, fully out-of-band from the request path) and will be swapped
for a Tetragon-based agent on the DigitalOcean Linux VPS deployment. Documented as a
deliberate deviation in docs/architecture.md.

Branch: **feat/capture-agent** owns `services/capture/**`.

To build here (Phase 0 has only `/health` + a validating `/ingest` stub):
- `app/producer.py` — `aiokafka.AIOKafkaProducer` created once in FastAPI lifespan,
  `acks=1`, small `linger_ms` batching; `send_and_wait` first for debuggability
  (fire-and-forget `send()` is the later throughput knob)
- Wire `/ingest` to the producer, keep 202 semantics
- Topic bootstrap: ensure `guardian.telemetry.raw` exists (3 partitions, ~6h retention —
  OpenSearch is the durable store, not the queue)

Event envelope contract: `app/schemas.py` (canonical spec: docs/architecture.md#event-schema).

Env vars: `REDPANDA_BROKERS` (default redpanda:9092), `TELEMETRY_TOPIC`. Port **8001**.
