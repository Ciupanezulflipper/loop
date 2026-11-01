import type { Agent } from "./types";

const BRIDGE_PREFIX_RE =
  /^(?:Message from (?:Claude|Codex) via the loop bridge:|(?:Claude|Codex):)\s*/i;

export const formatCodexBridgeMessage = (
  source: Agent,
  message: string
): string => {
  const trimmed = message.trim();
  if (!trimmed) {
    return "";
  }
  if (source !== "claude" || trimmed.startsWith("Claude:")) {
    return trimmed;
  }
  return `Claude: ${trimmed}`;
};

export const normalizeBridgeMessage = (message: string): string =>
  message.trim().replace(BRIDGE_PREFIX_RE, "").replace(/\s+/g, " ").trim();
