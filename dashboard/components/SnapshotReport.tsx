// WP-D: the print-only compliance report rendered from a FROZEN
// PulseSnapshot + NarrativeReport. Pure and static by design: every value is
// derived from props (client generation time = narrative.generated_at), no
// hooks, no Date.now(), no interactivity. Styled exclusively by app/print.css
// (sr-* classes) — the report is only ever visible in print.

import type {
  NarrativeReport,
  PulseSnapshot,
  ScorePoint,
  ScorerPulse,
} from "@/lib/types";

const SCORERS = ["argus", "sentinel", "cassandra"] as const;

function score3(n: number): string {
  return n.toFixed(3);
}

function iso(epochMs: number): string {
  return new Date(epochMs).toISOString();
}

function scorerRow(name: string, pulse: ScorerPulse) {
  const h = pulse.health;
  const status = h.ok ? h.data.status : "offline";
  const detail = h.ok
    ? `${h.data.service} — consumer ${h.data.consumer_connected ? "connected" : "disconnected"}`
    : `unreachable: ${h.error}`;
  return (
    <tr key={name}>
      <td className="sr-id">{name.toUpperCase()}</td>
      <td className={`sr-health sr-health-${status}`}>{status}</td>
      <td>{detail}</td>
    </tr>
  );
}

export default function SnapshotReport({
  snapshot,
  history,
  narrative,
}: {
  snapshot: PulseSnapshot;
  history: ScorePoint[];
  narrative: NarrativeReport;
}) {
  const fusion = snapshot.fusion;
  const scores = history.map((p) => p.score);

  return (
    <article className="sr-report">
      <header className="sr-header">
        <h1>GUARDIAN Pulse — Compliance Snapshot</h1>
        <dl className="sr-meta">
          <div>
            <dt>Report generated (client)</dt>
            <dd className="sr-num">{narrative.generated_at}</dd>
          </div>
          <div>
            <dt>Snapshot fetched (server)</dt>
            <dd className="sr-num">{snapshot.fetched_at}</dd>
          </div>
        </dl>
      </header>

      <section className="sr-section">
        <h2>Threat state</h2>
        {fusion.ok ? (
          <dl className="sr-stats">
            <div>
              <dt>Threat level</dt>
              <dd>
                <span
                  className={`sr-badge sr-level-${fusion.data.threat_level}`}
                >
                  <span className="sr-swatch" aria-hidden="true" />
                  {fusion.data.threat_level.toUpperCase()}
                </span>
              </dd>
            </div>
            <div>
              <dt>Anomaly score (decayed)</dt>
              <dd className="sr-num sr-big">{score3(fusion.data.anomaly_score)}</dd>
            </div>
            <div>
              <dt>Level since</dt>
              <dd className="sr-num">{fusion.data.level_since ?? "start of window"}</dd>
            </div>
            <div>
              <dt>Corroboration</dt>
              <dd className="sr-num">{fusion.data.corroboration}</dd>
            </div>
            <div>
              <dt>Entities tracked</dt>
              <dd className="sr-num">{fusion.data.entities_tracked}</dd>
            </div>
          </dl>
        ) : (
          <div className="sr-outage">
            <p>
              <strong>FUSION ENGINE UNREACHABLE at snapshot time.</strong>{" "}
              Threat level, contributors, top entities and transitions could
              not be collected; this outage record itself constitutes the
              compliance evidence for this instant.
            </p>
            <p className="sr-num">Error: {fusion.error}</p>
          </div>
        )}
      </section>

      <section className="sr-section">
        <h2>Incident narrative</h2>
        <p className="sr-headline">{narrative.headline}</p>
        {narrative.paragraphs.map((p, i) => (
          <p key={i}>{p}</p>
        ))}
        {narrative.bullets.length > 0 && (
          <ul>
            {narrative.bullets.map((b, i) => (
              <li key={i}>{b}</li>
            ))}
          </ul>
        )}
      </section>

      {fusion.ok && (
        <>
          <section className="sr-section">
            <h2>Model contributions</h2>
            {Object.keys(fusion.data.contributors).length === 0 ? (
              <p className="sr-empty">No active model contributions at snapshot time.</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Model</th>
                    <th className="sr-num-col">Strongest decayed claim</th>
                    <th className="sr-num-col">Fusion weight</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(fusion.data.contributors)
                    .sort(([, a], [, b]) => b - a)
                    .map(([model, claim]) => (
                      <tr key={model}>
                        <td className="sr-id">{model}</td>
                        <td className="sr-num-col">{score3(claim)}</td>
                        <td className="sr-num-col">
                          {fusion.data.config.weights[model] !== undefined
                            ? score3(fusion.data.config.weights[model])
                            : "—"}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            )}
          </section>

          <section className="sr-section">
            <h2>Top entities</h2>
            {fusion.data.top_entities.length === 0 ? (
              <p className="sr-empty">No scored entities at snapshot time.</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Entity</th>
                    <th className="sr-num-col">Score</th>
                    <th>Contributing models</th>
                    <th>Corroborated</th>
                    <th>Reasons</th>
                  </tr>
                </thead>
                <tbody>
                  {fusion.data.top_entities.map((e) => (
                    <tr key={`${e.entity_type}:${e.entity_id}`}>
                      <td>{e.entity_type}</td>
                      <td className="sr-id">{e.entity_id}</td>
                      <td className="sr-num-col">{score3(e.score)}</td>
                      <td className="sr-id">
                        {Object.entries(e.models)
                          .sort(([, a], [, b]) => b - a)
                          .map(([m, s]) => `${m} ${score3(s)}`)
                          .join(", ")}
                      </td>
                      <td>{e.corroborated ? "Yes" : "No"}</td>
                      <td className="sr-reasons">{e.reasons.join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <section className="sr-section">
            <h2>Recent threat-level transitions</h2>
            {fusion.data.recent_transitions.length === 0 ? (
              <p className="sr-empty">No transitions in the retention window.</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>At</th>
                    <th>Transition</th>
                    <th className="sr-num-col">Score</th>
                  </tr>
                </thead>
                <tbody>
                  {fusion.data.recent_transitions.map((t, i) => (
                    <tr key={i}>
                      <td className="sr-num">{t.at}</td>
                      <td>
                        {t.from.toUpperCase()} → {t.to.toUpperCase()}
                      </td>
                      <td className="sr-num-col">{score3(t.score)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </>
      )}

      <section className="sr-section">
        <h2>Scorer health</h2>
        <table>
          <thead>
            <tr>
              <th>Scorer</th>
              <th>Status</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>{SCORERS.map((s) => scorerRow(s, snapshot.scorers[s]))}</tbody>
        </table>
      </section>

      <section className="sr-section">
        <h2>Score history (HUD-accumulated)</h2>
        {history.length === 0 ? (
          <p className="sr-empty">
            No score samples accumulated before the freeze (fusion history is
            client-side only).
          </p>
        ) : (
          <dl className="sr-stats">
            <div>
              <dt>Samples</dt>
              <dd className="sr-num">{history.length}</dd>
            </div>
            <div>
              <dt>Window start</dt>
              <dd className="sr-num">{iso(history[0].t)}</dd>
            </div>
            <div>
              <dt>Window end</dt>
              <dd className="sr-num">{iso(history[history.length - 1].t)}</dd>
            </div>
            <div>
              <dt>Min score</dt>
              <dd className="sr-num">{score3(Math.min(...scores))}</dd>
            </div>
            <div>
              <dt>Max score</dt>
              <dd className="sr-num">{score3(Math.max(...scores))}</dd>
            </div>
            <div>
              <dt>Last score</dt>
              <dd className="sr-num">{score3(scores[scores.length - 1])}</dd>
            </div>
          </dl>
        )}
      </section>

      <footer className="sr-footer">
        Deterministic template-based narrative — no generative AI. Guardian
        Pulse audit snapshot.
      </footer>
    </article>
  );
}
