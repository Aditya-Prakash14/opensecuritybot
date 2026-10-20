export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "high" | "medium" | "low";

/** Normalized scanner finding. Unknown keys from the upstream tool pass through untouched. */
export interface Finding {
  id: string;
  target: string;
  title?: string;
  description?: string;
  severity?: string;
  tool?: string;
  raw?: unknown;
  [k: string]: unknown;
}

/** Operator-confirmed engagement scope. Read-only to the agent; enforced by scope-guard.ts. */
export interface Scope {
  engagement?: string;
  targets: Array<string | Record<string, unknown>>;
  exclude?: string[]; // never in scope, even when a target matches
  notBefore?: string; // ISO date: active scanning not allowed before
  notAfter?: string; // ISO date: active scanning not allowed after
  [k: string]: unknown;
}

export interface CveEntry {
  id: string;
  description?: string;
  cvss?: number;
  severity?: string;
  references: string[];
  kev?: boolean; // on the CISA Known Exploited Vulnerabilities catalog
}

/** Per-finding output schema (programmatic mode). */
export interface TriageResult {
  findingId: string;
  triage: {
    isLikelyTruePositive: boolean;
    reasoning: string;
    adjustedSeverity: Severity;
    owaspCategory: string | null;
  };
  explanation: string;
  remediation: {
    summary: string;
    steps: string[];
    references: string[];
  };
  confidence: Confidence;
  flaggedForManualReview: boolean;
}