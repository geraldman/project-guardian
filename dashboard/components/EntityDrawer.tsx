"use client";

// Entity drilldown drawer — the case file behind a Top Entities row. The HUD's
// verdict panels say WHO; this says WHY: each detector's own baseline state
// for the entity plus its most recent raw events, fetched on open from
// /api/entity. Every section degrades independently (SourceResult), and a
// section that is structurally not applicable (cassandra for an IP) explains
// itself instead of rendering an error.

import { useEffect, useRef, useState } from "react";
import type {
  ArgusBaseline,
  ArgusIpCohort,
  CassandraBaseline,
  CusumSeriesState,
  EntityCaseFile,
  EntityDrawerProps,
  EntityEvent,
  SourceResult,
} from "@/lib/types";
import styles from "./EntityDrawer.module.css";

function sigma(v: number): number {
  return Math.sqrt(Math.max(v, 0));
}

function fmt(n: number, digits = 2): string {
  if (!Number.isFinite(n)) return "—";
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (Math.abs(n) >= 10_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toFixed(digits);
}

function clock(iso: string): string {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? "—" : new Date(t).toLocaleTimeString("en-GB");
}

// ── ARGUS section ───────────────────────────────────────────────────────────

const FEATURE_LABELS: Record<string, string> = {
  rate: "event rate / min",
  payload: "payload bytes",
  error: "error rate",
};

function ArgusSection({ result }: { result: SourceResult<ArgusBaseline | ArgusIpCohort> | null }) {
  if (result === null) return null;
  if (!result.ok) {
    return <p className={styles.sectionNote}>baseline unavailable — {result.error}</p>;
  }
  const data = result.data;

  if ("cohort" in data) {
    // client_ip: one EWStats over per-IP minute rates, cohort-wide by design.
    return (
      <dl className={styles.statList}>
        <div className={styles.statRow}>
          <dt>cohort rate / min</dt>
          <dd>
            {fmt(data.cohort.mean)} <span className={styles.dim}>± {fmt(sigma(data.cohort.var))}</span>
          </dd>
        </div>
        <div className={styles.statRow}>
          <dt>cohort samples</dt>
          <dd>{data.cohort.n}</dd>
        </div>
        <p className={styles.sectionNote}>
          IP baselines are cohort-wide: an IP is anomalous against how IPs in general behave,
          not against its own history.
        </p>
      </dl>
    );
  }

  return (
    <dl className={styles.statList}>
      {Object.entries(data.features).map(([name, s]) => (
        <div key={name} className={styles.statRow}>
          <dt>{FEATURE_LABELS[name] ?? name}</dt>
          <dd>
            {fmt(s.mean)} <span className={styles.dim}>± {fmt(sigma(s.var))}</span>
            <span className={styles.dim}> · n={s.n}</span>
          </dd>
        </div>
      ))}
      {data.warming_up && <p className={styles.sectionNote}>still warming up — treat with caution</p>}
    </dl>
  );
}

// ── CASSANDRA section ───────────────────────────────────────────────────────

function CusumMeter({
  label,
  series,
  h,
  hSingle,
}: {
  label: string;
  series: CusumSeriesState;
  h: number | null;
  hSingle: number | null;
}) {
  // Scale runs to the single-series alarm bar (the farthest threshold) plus
  // headroom, so both thresholds are always on-scale.
  const cap = Math.max(hSingle ?? 0, h ?? 0, series.s) * 1.15 || 1;
  const ratio = h && h > 0 ? series.s / h : 0;
  const tone = ratio >= 1 ? styles.fillAlarm : ratio >= 0.6 ? styles.fillWarn : styles.fillCalm;
  return (
    <div className={styles.meterBlock}>
      <div className={styles.meterHead}>
        <span>{label}</span>
        <span className={styles.meterValue}>
          S = {fmt(series.s)}
          {h !== null && <span className={styles.dim}> / h {fmt(h, 1)}</span>}
        </span>
      </div>
      <div className={styles.meterTrack}>
        <div className={`${styles.meterFill} ${tone}`} style={{ width: `${Math.min(series.s / cap, 1) * 100}%` }} />
        {h !== null && <span className={styles.meterMark} style={{ left: `${(h / cap) * 100}%` }} title={`paired alarm threshold h = ${h}`} />}
        {hSingle !== null && (
          <span className={`${styles.meterMark} ${styles.meterMarkSingle}`} style={{ left: `${(hSingle / cap) * 100}%` }} title={`single-series alarm threshold = ${hSingle}`} />
        )}
      </div>
      <div className={styles.meterFoot}>
        <span>
          baseline {fmt(series.baseline.mean)} <span className={styles.dim}>± {fmt(sigma(series.baseline.var))}</span>
        </span>
        <span className={styles.dim}>run {series.run} · ewma z {fmt(series.ewma_z)}</span>
      </div>
    </div>
  );
}

function CassandraSection({
  result,
  entityType,
  config,
}: {
  result: SourceResult<CassandraBaseline> | null;
  entityType: string;
  config: { h: number | null; hSingle: number | null };
}) {
  if (result === null) {
    return (
      <p className={styles.sectionNote}>
        not applicable — CASSANDRA baselines payers only{entityType === "client_ip" ? "; IPs are ARGUS territory" : ""}
      </p>
    );
  }
  if (!result.ok) {
    return <p className={styles.sectionNote}>baseline unavailable — {result.error}</p>;
  }
  const d = result.data;
  return (
    <div>
      <CusumMeter label="volume drift" series={d.volume} h={config.h} hSingle={config.hSingle} />
      <CusumMeter label="amount drift" series={d.amount} h={config.h} hSingle={config.hSingle} />
      <p className={styles.sectionNote}>
        {d.buckets_observed} buckets observed{d.warming_up ? " — still warming up" : ""}
      </p>
    </div>
  );
}

// ── Events section ──────────────────────────────────────────────────────────

function EventRow({ ev, entityType }: { ev: EntityEvent; entityType: string }) {
  // Show the counterpart identity: drilling a payer, you want the IPs; drilling
  // an IP, you want the payers.
  const counterpart = entityType === "payer" ? ev.client_ip : ev.payer_id;
  return (
    <li className={styles.eventRow} title={ev.message ?? undefined}>
      <span className={styles.eventTime}>{clock(ev.t)}</span>
      <span className={styles.eventBody}>
        {counterpart && <span className={styles.eventCounterpart}>{counterpart}</span>}
        {ev.status && <span className={styles.dim}> {ev.status}</span>}
        {ev.amount !== null && (
          <span className={styles.dim}>
            {" "}
            {fmt(ev.amount, 0)} {ev.currency ?? ""}
          </span>
        )}
      </span>
      <span className={styles.eventFlags}>
        {ev.is_attack && <span className={styles.flagAttack}>{ev.attack_pattern ?? "attack"}</span>}
        {ev.error && !ev.is_attack && <span className={styles.flagError}>error</span>}
      </span>
    </li>
  );
}

// ── Drawer shell ────────────────────────────────────────────────────────────

export default function EntityDrawer({ snapshot, entity, onClose }: EntityDrawerProps) {
  const [caseFile, setCaseFile] = useState<EntityCaseFile | null>(null);
  const [failed, setFailed] = useState(false);
  const closeRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (!entity) return;
    setCaseFile(null);
    setFailed(false);
    let cancelled = false;
    const url = `/api/entity?type=${encodeURIComponent(entity.entity_type)}&id=${encodeURIComponent(entity.entity_id)}`;
    fetch(url, { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((d: EntityCaseFile) => {
        if (!cancelled) setCaseFile(d);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, [entity]);

  useEffect(() => {
    if (!entity) return;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [entity, onClose]);

  if (!entity) return null;

  const cassandraStats = snapshot?.scorers.cassandra.stats;
  const cassandraConfig =
    cassandraStats?.ok && typeof cassandraStats.data.config === "object" && cassandraStats.data.config !== null
      ? (cassandraStats.data.config as Record<string, unknown>)
      : null;
  const numOrNull = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);

  return (
    <div className={styles.overlay}>
      <button className={styles.backdrop} aria-label="close drilldown" onClick={onClose} tabIndex={-1} />
      <aside className={styles.drawer} role="dialog" aria-modal="true" aria-label={`case file for ${entity.entity_id}`}>
        <header className={styles.head}>
          <div>
            <div className={styles.kicker}>{entity.entity_type} · case file</div>
            <h2 className={styles.title}>{entity.entity_id}</h2>
          </div>
          <button ref={closeRef} className={styles.close} onClick={onClose}>
            esc
          </button>
        </header>

        <div className={styles.verdict}>
          <span className={styles.scoreBig}>{entity.score.toFixed(2)}</span>
          <span className={styles.dim}>fused score</span>
          {entity.corroborated && <span className={styles.corroborated}>corroborated</span>}
        </div>
        {entity.reasons.length > 0 && (
          <div className={styles.reasons}>
            {entity.reasons.map((r) => (
              <span key={r} className={styles.tag}>
                {r.replace(/_/g, " ")}
              </span>
            ))}
          </div>
        )}

        {failed && <p className={styles.sectionNote}>case file fetch failed — is the HUD proxy up?</p>}
        {!caseFile && !failed && <p className={styles.sectionNote}>assembling case file…</p>}

        {caseFile && (
          <div className={styles.sections}>
            <section>
              <h3 className={styles.sectionTitle}>ARGUS · behavioral baseline</h3>
              <ArgusSection result={caseFile.argus} />
            </section>

            <section>
              <h3 className={styles.sectionTitle}>CASSANDRA · drift state</h3>
              <CassandraSection
                result={caseFile.cassandra}
                entityType={entity.entity_type}
                config={{
                  h: numOrNull(cassandraConfig?.cusum_h),
                  hSingle: numOrNull(cassandraConfig?.cusum_h_single),
                }}
              />
            </section>

            <section className={styles.eventsSection}>
              <h3 className={styles.sectionTitle}>
                recent events
                {caseFile.events.ok && <span className={styles.dim}> · {caseFile.events.data.length}</span>}
              </h3>
              {!caseFile.events.ok ? (
                <p className={styles.sectionNote}>events unavailable — {caseFile.events.error}</p>
              ) : caseFile.events.data.length === 0 ? (
                <p className={styles.sectionNote}>no events indexed for this entity</p>
              ) : (
                <ul className={styles.events}>
                  {caseFile.events.data.map((ev, i) => (
                    <EventRow key={`${ev.t}-${i}`} ev={ev} entityType={entity.entity_type} />
                  ))}
                </ul>
              )}
            </section>
          </div>
        )}
      </aside>
    </div>
  );
}
