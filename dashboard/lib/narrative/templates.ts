// Fixed template fragments for the incident narrative (WP-C).
// The tag vocabulary mirrors what fusion's _reason_tag() actually produces
// (services/fusion/app/engine.py): scorer-specific tags plus sentinel
// template names passed through verbatim and a trimmed-token fallback.

import type { ThreatLevel } from "../types";

export const HEADLINES: Record<ThreatLevel, string> = {
  normal: "Situation normal — no corroborated anomalous activity",
  elevated: "ELEVATED — anomalous activity under observation",
  critical: "CRITICAL — corroborated anomalous activity in progress",
};

export const OFFLINE_HEADLINE = "Threat picture unavailable — fusion engine unreachable";

export const MODEL_NAMES: Record<string, string> = {
  argus: "ARGUS",
  sentinel: "SENTINEL",
  cassandra: "CASSANDRA",
};

export const REASON_TEXT: Record<string, string> = {
  // ARGUS (statistical)
  rate_spike: "a spike in request rate",
  payload_anomaly: "anomalous payload sizes",
  error_ratio_spike: "a surge in error responses",
  multivariate_outlier: "an unusual combination of traffic features",
  // SENTINEL (behavioral ML; template names pass through _reason_tag)
  sqli_probe: "SQL-injection probing",
  path_traversal: "path-traversal attempts",
  scanner_probe: "automated scanner probing",
  auth_failure: "repeated authentication failures",
  auth_fail_ratio: "an abnormal authentication-failure ratio",
  model_p_malicious: "behaviour the ML model rates as likely malicious",
  log_classification: "suspicious log patterns",
  // CASSANDRA (drift / CUSUM)
  slow_exfiltration: "a slow data-exfiltration pattern",
  // Fusion default
  anomalous: "anomalous behaviour",
};
