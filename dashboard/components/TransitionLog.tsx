// Stub — rewritten by WP-A (feat/pulse-threat). Props are frozen contract.

import type { TransitionLogProps } from "@/lib/types";

export default function TransitionLog({ snapshot }: TransitionLogProps) {
  const count = snapshot?.fusion.ok ? snapshot.fusion.data.recent_transitions.length : 0;
  return (
    <div className="panel">
      <div className="panel-title">Transitions</div>
      <div className="stub">{count} recorded — pending WP-A</div>
    </div>
  );
}
