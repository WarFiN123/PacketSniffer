// Shared interception-rule types and defaults. The shape mirrors the Rust
// `proxy::intercept::InterceptConfig` (serde camelCase) — keep them in sync.

export type ListMode = "off" | "block" | "allow";
export type MapKind = "local" | "remote";

export interface MapRule {
  pattern: string;
  kind: MapKind;
  target: string;
  enabled: boolean;
}

export interface InterceptConfig {
  noCache: boolean;
  listMode: ListMode;
  listRules: string[];
  mapRules: MapRule[];
  latencyMs: number;
  kbps: number;
}

export const DEFAULT_INTERCEPT: InterceptConfig = {
  noCache: false,
  listMode: "off",
  listRules: [],
  mapRules: [],
  latencyMs: 0,
  kbps: 0,
};

export const NET_PRESETS: { name: string; latencyMs: number; kbps: number }[] = [
  { name: "Online (no limit)", latencyMs: 0, kbps: 0 },
  { name: "GPRS", latencyMs: 500, kbps: 50 },
  { name: "Slow 3G", latencyMs: 400, kbps: 400 },
  { name: "Fast 3G", latencyMs: 150, kbps: 1600 },
  { name: "4G / LTE", latencyMs: 60, kbps: 9000 },
];
