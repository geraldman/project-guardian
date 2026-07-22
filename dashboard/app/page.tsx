"use client";

// HUD shell: single usePulse() call, grid of panels ordered by the questions an
// operator actually asks — how bad is it (threat), who is doing it (entities),
// can I trust the verdict (heartbeats), what happened (narrative/transitions).
// Panels receive exactly the props declared in lib/types.ts.

import { usePulse } from "@/lib/usePulse";
import ThreatIndicator from "@/components/ThreatIndicator";
import TopEntities from "@/components/TopEntities";
import TransitionLog from "@/components/TransitionLog";
import HeartbeatRow from "@/components/HeartbeatRow";
import NarrativePanel from "@/components/NarrativePanel";
import ContextStrip from "@/components/ContextStrip";
import FreezeButton from "@/components/FreezeButton";

export default function Home() {
  const { snapshot, history, status, rates } = usePulse();

  // Drives page-level treatment so the state is legible from across a room,
  // not just from the lamp. "offline" is distinct from "normal": no data is
  // not the same as no threat.
  const level = snapshot?.fusion.ok ? snapshot.fusion.data.threat_level : "offline";

  return (
    <main className="hud-root" data-level={level}>
      <header className="hud-header">
        <div className="hud-brand">
          <h1>Guardian Pulse</h1>
          <span className={`hud-status hud-status-${status}`}>{status}</span>
        </div>
        <ContextStrip snapshot={snapshot} rates={rates} />
      </header>

      <div className="hud-grid">
        <section className="hud-area-threat">
          <ThreatIndicator snapshot={snapshot} history={history} status={status} />
        </section>
        <section className="hud-area-entities">
          <TopEntities snapshot={snapshot} />
        </section>
        <section className="hud-area-side">
          <TransitionLog snapshot={snapshot} />
          <FreezeButton snapshot={snapshot} history={history} />
        </section>
        <section className="hud-area-heartbeats">
          <HeartbeatRow snapshot={snapshot} rates={rates} />
        </section>
        <section className="hud-area-narrative">
          <NarrativePanel snapshot={snapshot} />
        </section>
      </div>
    </main>
  );
}
