# GUARDIAN load test — measuring the 5M events/day claim

**Date:** 2026-07-15 · **Harness:** [`scripts/load_test.py`](../scripts/load_test.py)

The brief sizes LTI's traffic at **5M+ transactions/day (~58 events/s sustained)** and
grades on scalability. This report replaces the manuals' former "~4–5 GB, should cope"
estimates with measured numbers from driving the real stack through rate steps on a
development laptop.

## Verdict

| Claim | Result |
|---|---|
| Ingestion → indexing at 5M/day (the §5.1 mandatory pipeline) | **PASS** — zero telemetry loss, indexing keeps pace, consumer lag stays in seconds |
| Detection triad at 5M/day | **PASS in steady state** — all three scorers held 58 ev/s for 30 minutes with zero lag. SENTINEL is the CPU-dominant component and backlogs gracefully (delayed, never dropped) under bursts beyond ~60–80 ev/s or heavy co-contention (see below) |
| Pipeline throughput ceiling | **≥ ~109 ev/s observed with zero loss** — bounded by the load *generator*, not the pipeline |
| RAM (whole 14-service stack) | **~2.5 GiB under 5M/day load** — the old 4–5 GB estimate was nearly double reality |

## Environment (honest caveats)

- Windows 11 laptop, 12 logical CPUs, Docker Desktop (WSL2) VM capped at **6.7 GiB**
  (below the manuals' recommended 8 GiB — the stack fit anyway).
- One unrelated container (~95 MiB, idle) shared the VM during the test.
- Measurements are HTTP counter deltas sampled every 15 s (generator status, scorer
  `/stats`, fusion `/threat`, alerting `/stats`, OpenSearch `_count`), so rates are
  immune to sampling jitter; RAM/CPU from `docker stats`; consumer lag cross-checked
  with `rpk group describe` mid-run.

## Run 1 — ceiling search (8 min per step, attacks off)

| target ev/s | achieved emit/s | lost | indexed/s | notes |
|---|---|---|---|---|
| 10 | 10.0 | 0 | 10.2 | clean baseline |
| **58** | **58.0** | **0** | **59.4** | 5M/day: transport clean; SENTINEL starts backlogging |
| 120 | 80.3 | 0 | 81.3 | generator flat-out ceiling reached |
| 250 | 79.2 | 14 | 78.7 | generator ceiling; first touch of its drop valve |
| 500 | 108.6 | 0 | 107.6 | best observed throughput — still zero loss |
| 1000 | 47.6 | 1,038 | 0 | load-source collapse (see incident below); harness abort guard tripped |

Whole-run totals (41.7 min): **164,285 events sent; ARGUS consumed 164,168, CASSANDRA
164,267, OpenSearch indexed 164,511** (≥100% — catch-up included) at an average 65.7 ev/s.
Vector's consumer lag never exceeded ~460 events (≈5 s of traffic); `rpk group describe`
mid-run showed Vector/ARGUS/CASSANDRA lags of 349/478/183 events respectively.

## Run 2 — sustained 5M/day (58 ev/s × 30 min)

Run after the emitter fix, attacks off. Over **29.9 minutes**:

| metric | value |
|---|---|
| emitted / lost | **103,893 / 0** |
| achieved emit rate | **58.00 ev/s** (target 58) |
| indexed rate | **57.99 docs/s** (end-of-run lag: −32, i.e. fully caught up) |
| ARGUS / SENTINEL / CASSANDRA consumption | **58.00 / 58.01 / 58.01 ev/s — zero lag, all three** |
| threat level | critical throughout (the sustained rate step is itself the anomaly — see below) |

**A 30-minute hold at the 5M/day rate passes end-to-end, detection triad included.**

The sustain run also corrected an interim conclusion from the ceiling search: SENTINEL's
apparent ~20 ev/s limit there was *CPU contention*, not an architectural ceiling. With
the generator running flat-out (80–109 ev/s) the whole VM was oversubscribed and
SENTINEL — the hungriest component — degraded to ~20 ev/s and backlogged ~35k events.
During the quiet window after the ceiling run it drained that entire backlog at 60+ ev/s,
and in steady state at 58 ev/s it keeps pace exactly.

## The CPU-dominant component: SENTINEL

SENTINEL (Drain3 template mining + windowed XGBoost, one Python process) pinned
~8.6 of the VM's 12 cores from the 58 ev/s step onward — by far the hungriest
component. Its behavior splits cleanly into two regimes:

- **Steady state at 5M/day: keeps pace exactly** (58.01 ev/s over the 30-minute hold,
  zero lag), with headroom demonstrated by draining a ~126k-event backlog at 60+ ev/s
  on an otherwise-quiet stack.
- **Under co-contention** (the ceiling search, generator flat-out at 80–109 ev/s,
  whole VM pegged) it degraded to ~20 ev/s and backlogged ~35,200 events
  (`rpk group describe guardian-sentinel`, mid-run). Two qualifiers keep that
  behavior acceptable: **nothing is lost** — Redpanda buffers the backlog (≈6 h
  retention at these volumes) and detections are delayed, not dropped, which is the
  brief's "sized for spikes" requirement doing its job; and **its control plane
  degrades first** — `/stats`/`/health` timeouts from the CPU-starved event loop are
  an early-warning signal that appears well before any data-plane loss.

Growth path beyond ~60–80 ev/s (already pinned in the admin manual): produce keyed by
entity and add SENTINEL consumers up to the topic's 3 partitions, or optimize the
single instance (template-cache tuning, batch scoring). More CPU also works — the
limit observed here is compute, not architecture.

## The load-source incident at 1000 ev/s (resilience finding)

At the 1000 ev/s target the *generator itself* collapsed: the flood of timeouts
poisoned mock-lti's shared HTTP client (leaked connection-pool slots), after which
**every** send failed in ~2 s — including at baseline rates, permanently. Meanwhile the
GUARDIAN pipeline survived the same flood untouched: capture, Redpanda, Vector,
OpenSearch, all three scorers and fusion sat healthy waiting for traffic.

Fixed in `services/mock-lti/app/telemetry.py`: after 50 consecutive send failures the
emitter swaps in a fresh client (self-heal), restoring its design doctrine that a
capture hiccup must never stall traffic generation. The sustained run below was
executed after this fix.

## RAM — measured, replacing the 4–5 GB estimate

`docker stats` during the 58 ev/s plateau (whole stack including HUD and consoles):
**~2.5 GiB total.** OpenSearch 1.42 GiB and Redpanda 313 MiB dominate; every scorer
stays under 120 MiB; totals moved by only ~60 MiB from baseline to the 120 ev/s step.
Memory is not the pressure axis at these volumes — **CPU is** (SENTINEL above).

## Detection layer during the test (expected storm, observed)

A rate step is a genuine global anomaly, and the SIEM said so: threat level walked
normal → elevated → critical during the 58 ev/s step; ARGUS raised `rate_spike`;
CASSANDRA's per-payer CUSUM charts charged on the sustained step. Alerting's 5-minute
dedup contained the storm to **205 alerts sent / 132 suppressed** across the whole
ceiling run (log-only mode). 44,478 score documents were indexed alongside the traffic
without disturbing indexing throughput.

## Post-test recovery

Load-skewed baselines are reset rather than left to re-adapt (hours):

```sh
docker compose stop argus cassandra
docker volume rm guardian_argus-data guardian_cassandra-data
docker compose up -d argus cassandra
python training/seed_history.py    # re-warm CASSANDRA + ARGUS (~1 min)
```

SENTINEL keeps no volume state and needed nothing here (it had fully drained its
backlog by the end of the test). If a future test leaves it with a large stale backlog,
skip it while the service is stopped — `docker compose stop sentinel`, then
`docker compose exec redpanda rpk group seek guardian-sentinel --to end`, then start it
again; that discards only stale windows (fusion ignores stale scores anyway). Fusion
self-heals in minutes by design.
