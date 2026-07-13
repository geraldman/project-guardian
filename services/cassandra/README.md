# CASSANDRA — slow-exfiltration detector

Catches the attack ARGUS is structurally blind to: **low-and-slow exfiltration**
that stays under per-minute rate thresholds (the generator's `slow_exfil` mode:
~2 extra events/min on one payer at ~1.8× amounts — beneath ARGUS's 3σ/minute
detectors and its minimum-volume alert floor). Locally such traffic is normal;
it is only abnormal *cumulatively*. So the unit of analysis is never the single
event: events are aggregated into per-payer 1-minute buckets (count, amount
moved, distinct payees), and detection runs on the aggregated series.

Consumes `guardian.telemetry.normalized` (group `guardian-cassandra`), emits
`score.model: "cassandra"` documents to `guardian.scores` and
`alert.type: "slow_exfiltration"` to `guardian.alerts`. Pure Kafka-in/Kafka-out;
Vector owns the OpenSearch write path.

## Detection design

Per payer, two one-sided upper **CUSUM control charts** — event volume and
(winsorized) amount moved:

    z_t = clip((x_t − μ) / σ, ±z_clip)          μ, σ from the payer's own baseline
    S_t = min(max(0, S_{t−1} + z_t − k), s_cap)

- **Per-entity calibration.** μ/σ are learned per payer (two-phase: plain
  sample statistics over the first `warmup_buckets`, then a slow 240-bucket
  half-life exponential window). Sigma floors encode observable granularity —
  a payer's minute-count is never treated as more predictable than ±1 event,
  its minute-amount never tighter than ±1 typical event (200k IDR) — so
  low-rate payers can't manufacture z-scores out of discreteness noise.
- **Winsorization.** Each event's amount is capped (`amount_event_cap`, 1M IDR
  ≈ p97) before summing: amounts are lognormal-heavy-tailed and one benign
  whale must not buy an alarm — an exfil trickle's extra *events* lift the
  capped sum regardless.
- **Absence is signal.** Once tracked, a payer absent from a bucket is scored
  as a zero observation — a baseline learned only over active minutes would
  miss the trickle's main effect (more active minutes).
- **Attack-absorption guard.** A chart in a material excursion
  (`S ≥ baseline_freeze_s`) freezes its baseline so a persisting attack can't
  teach itself into normality. The freeze sits **at** the joint alarm bar `h`,
  not below: a slightly miscalibrated benign baseline must stay able to
  self-correct, or the freeze deadlocks it into a guaranteed false alarm.

**Alarm policy** — sustained multi-bucket drift only, and the volume chart is
always involved (amounts corroborate, never accuse alone — their heavy-tailed
z is asymmetric and drifts upward on benign whales):

| Path | Condition |
|---|---|
| joint | volume **and** amount CUSUM ≥ `h` |
| volume-only | volume CUSUM ≥ `h_single` (exfil whose amounts ride under the cap) |

Either path additionally requires the excursion to have lasted
`min_drift_buckets` and the short-half-life EWMA of recent z to still be
elevated (`ewma_alarm_floor`) — a couple of clipped benign spikes cannot alarm.
Payers younger than `warmup_buckets` observed minutes never alarm (cold-start
guard); `/health` exposes `payers_warm`.

## False-alarm rate (measured, shipped defaults)

CUSUM's point is that the false-alarm rate is a *quantified trade-off*, not
zero. Offline validation (`tests/offline_check.py`) measures, at k=0.75, h=6,
h_single=10, drift=6, ewma=0.9:

- **benign**: ~2 alarm episodes per ~3,100 benign payer-hours (26 seeded
  120-minute economies of 41 payers); the fleet soak budget-checks 700 payers
  × 6h against ≤8 episodes.
- **slow_exfil** (generator defaults on a warm baseline): 25/25 seeds
  detected, median delay 9 min, worst tail 25 min (Poisson luck on ~2/min).

Retuning: `k` is the shift size you're willing to be slow about (σ units);
`h`/`h_single` trade delay for ARL. After any change, rerun
`python services/cassandra/tests/offline_check.py` (host Python, no stack
needed) — it re-measures both sides of the trade-off.

## Warm-up / seeding

A payer may alarm only after `warmup_buckets` (default 30) observed minutes.
Production framing: "N days of clean history per entity before activation" —
the demo compresses it to 30 minutes. Two bootstraps:

- fresh consumer group: `auto_offset_reset=earliest` replays the queue's ~6h
  retention window — real history is the primary warm-up;
- fresh stack (empty queue): `python training/seed_history.py` replays 40
  backdated benign minutes through the real pipeline (also warms ARGUS).

State (baselines + open excursions) snapshots to `STATE_PATH` every 60s and on
shutdown; restarts resume warm (compose needs a `cassandra-data` volume for
this to survive container recreation — without it, worst case is a re-warm-up).

## Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /health` | liveness + consumer state + warm-up progress |
| `GET /stats` | pipeline counters + effective detection config |
| `GET /drift/top` | payers closest to (or over) the alarm bar |
| `GET /baseline/payer/{id}` | one payer's charts and baseline |

## Configuration

All knobs are env vars with working defaults (see `app/config.py`); the
compose block sets only broker/topics. Notable: `WARMUP_BUCKETS`, `CUSUM_K`,
`CUSUM_H`, `CUSUM_H_SINGLE`, `MIN_DRIFT_BUCKETS`, `EWMA_ALARM_FLOOR`,
`AMOUNT_EVENT_CAP`, `STATE_PATH`.
