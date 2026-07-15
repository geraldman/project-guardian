"use client";

// HUD shell (WP-0, frozen): single usePulse() call, grid of panels.
// Panels receive exactly the props declared in lib/types.ts.

import { usePulse } from "@/lib/usePulse";
import ThreatIndicator from "@/components/ThreatIndicator";
import TransitionLog from "@/components/TransitionLog";
import HeartbeatRow from "@/components/HeartbeatRow";
import NarrativePanel from "@/components/NarrativePanel";
import FreezeButton from "@/components/FreezeButton";

export default function Home() {
  const { snapshot, history, status } = usePulse();

  return (
    <main className="hud-root">
      <header className="hud-header">
        <h1>Guardian Pulse</h1>
        <span className={`hud-status hud-status-${status}`}>{status}</span>
      </header>
      <div className="hud-grid">
        <section className="hud-area-threat">
          <ThreatIndicator snapshot={snapshot} history={history} status={status} />
        </section>
        <section className="hud-area-heartbeats">
          <HeartbeatRow snapshot={snapshot} />
        </section>
        <section className="hud-area-narrative">
          <NarrativePanel snapshot={snapshot} />
        </section>
        <section className="hud-area-side">
          <TransitionLog snapshot={snapshot} />
          <FreezeButton snapshot={snapshot} history={history} />
        </section>
      </div>
    </main>
  );
}
