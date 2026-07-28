"use client";

// Top entities panel: the "who" of an incident. fusion's snapshot already ranks
// entities by fused score with a per-model breakdown and a corroboration flag;
// before this panel existed that ranking only ever reached the printed report
// and the narrative prose, so the live HUD could not answer "which payer?".

import { useEffect, useState } from "react";
import type { ModelName, TopEntitiesProps, TopEntity } from "@/lib/types";
import styles from "./TopEntities.module.css";

const MODELS: readonly ModelName[] = ["argus", "sentinel", "cassandra"];
const SHORT: Record<ModelName, string> = { argus: "A", sentinel: "S", cassandra: "C" };
const VISIBLE = 6;

function relativeAge(iso: string, now: number): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  return `${Math.floor(s / 3600)}h`;
}

// "sentinel:path_traversal" -> "path traversal"; bare tags pass through.
function readableReason(reason: string): string {
  const tag = reason.includes(":") ? reason.slice(reason.indexOf(":") + 1) : reason;
  return tag.replace(/_/g, " ");
}

function EntityRow({
  entity,
  now,
  onSelect,
}: {
  entity: TopEntity;
  now: number;
  onSelect?: (entity: TopEntity) => void;
}) {
  const score = Math.min(1, Math.max(0, entity.score));
  return (
    <li
      className={`${styles.row} ${onSelect ? styles.rowClickable : ""}`}
      onClick={onSelect ? () => onSelect(entity) : undefined}
      onKeyDown={
        onSelect
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onSelect(entity);
              }
            }
          : undefined
      }
      role={onSelect ? "button" : undefined}
      tabIndex={onSelect ? 0 : undefined}
      title={onSelect ? "open case file" : undefined}
    >
      <div className={styles.line}>
        <span className={styles.id} title={`${entity.entity_type}:${entity.entity_id}`}>
          {entity.entity_id}
        </span>
        {entity.corroborated && (
          <span className={styles.corroborated} title="flagged by more than one model">
            ✦ corroborated
          </span>
        )}
        <span className={styles.age}>{relativeAge(entity.last_update, now)}</span>
      </div>

      <div className={styles.line}>
        <span className={styles.type}>{entity.entity_type}</span>
        <span className={styles.track} aria-hidden="true">
          <span
            className={`${styles.fill} ${entity.corroborated ? styles.fillCorroborated : ""}`}
            style={{ width: `${score * 100}%` }}
          />
        </span>
        <span className={styles.score}>{entity.score.toFixed(2)}</span>
        <span className={styles.models}>
          {MODELS.map((m) => {
            const v = entity.models[m];
            const active = typeof v === "number" && Number.isFinite(v) && v > 0;
            return (
              <span
                key={m}
                className={`${styles.modelDot} ${active ? styles[m] : styles.modelIdle}`}
                title={active ? `${m}: ${(v as number).toFixed(2)}` : `${m}: no claim`}
              >
                {SHORT[m]}
              </span>
            );
          })}
        </span>
      </div>

      {entity.reasons.length > 0 && (
        <div className={styles.reasons}>
          {entity.reasons.slice(0, 4).map((r) => (
            <span key={r} className={styles.tag} title={r}>
              {readableReason(r)}
            </span>
          ))}
        </div>
      )}
    </li>
  );
}

export default function TopEntities({ snapshot, onSelect }: TopEntitiesProps) {
  // Ages are relative to a ticking clock, not to the poll, so "12s" keeps
  // counting between snapshots instead of freezing for 5 seconds at a time.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const fusion = snapshot?.fusion;
  const threat = fusion?.ok ? fusion.data : null;
  const entities = threat?.top_entities ?? [];

  return (
    <div className={`panel ${styles.root}`}>
      <div className={styles.head}>
        <div className="panel-title">Entities Under Suspicion</div>
        {threat && (
          <span className={styles.tracked}>{threat.entities_tracked} tracked</span>
        )}
      </div>

      {!threat ? (
        <div className={styles.empty}>
          {fusion && !fusion.ok ? "fusion unreachable" : "awaiting first snapshot"}
        </div>
      ) : entities.length === 0 ? (
        <div className={styles.empty}>
          no entity above the contribution floor
          <span className={styles.emptyHint}>nothing is currently accusing anyone</span>
        </div>
      ) : (
        <ol className={styles.list}>
          {entities.slice(0, VISIBLE).map((e) => (
            <EntityRow key={`${e.entity_type}:${e.entity_id}`} entity={e} now={now} onSelect={onSelect} />
          ))}
        </ol>
      )}

      {entities.length > VISIBLE && (
        <div className={styles.more}>+{entities.length - VISIBLE} more</div>
      )}
    </div>
  );
}
