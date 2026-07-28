"use client";

// HUD shell: single usePulse() call, grid of panels ordered by the questions an
// operator actually asks — how bad is it (threat), who is doing it (entities),
// can I trust the verdict (heartbeats), what happened (narrative/transitions).
// Panels receive exactly the props declared in lib/types.ts.

import { useCallback, useState } from "react";
import { usePulse } from "@/lib/usePulse";
import type { TopEntity } from "@/lib/types";
import ThreatIndicator from "@/components/ThreatIndicator";
import TopEntities from "@/components/TopEntities";
import TransitionLog from "@/components/TransitionLog";
import HeartbeatRow from "@/components/HeartbeatRow";
import NarrativePanel from "@/components/NarrativePanel";
import ContextStrip from "@/components/ContextStrip";
import FreezeButton from "@/components/FreezeButton";
import TrafficPanel from "@/components/TrafficPanel";
import EntityDrawer from "@/components/EntityDrawer";

export default function Home() {
  const { snapshot, history, status, rates } = usePulse();
  const [selected, setSelected] = useState<TopEntity | null>(null);

  // The traffic panel's top lists open the same case-file drawer as a Top
  // Entities row; entities picked there carry no fusion claim yet, so the
  // verdict header renders from a zeroed stand-in.
  const selectByName = useCallback((entityType: string, entityId: string) => {
    setSelected({
      entity_type: entityType,
      entity_id: entityId,
      score: 0,
      models: {},
      corroborated: false,
      reasons: [],
      last_update: new Date().toISOString(),
    });
  }, []);

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
          <TopEntities snapshot={snapshot} onSelect={setSelected} />
        </section>
        <section className="hud-area-side">
          <TransitionLog snapshot={snapshot} />
          <FreezeButton snapshot={snapshot} history={history} />
        </section>
        <section className="hud-area-heartbeats">
          <HeartbeatRow snapshot={snapshot} rates={rates} />
        </section>
        <section className="hud-area-traffic">
          <TrafficPanel onSelect={selectByName} />
        </section>
        <section className="hud-area-narrative">
          <NarrativePanel snapshot={snapshot} />
        </section>
      </div>

      <EntityDrawer snapshot={snapshot} entity={selected} onClose={() => setSelected(null)} />
    </main>
  );
}
