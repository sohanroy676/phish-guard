import type { Band } from "./api";

// Fixed wording from ADR 0002. There is deliberately no "Safe".
export const BAND_LABELS: Record<Band, string> = {
  high: "Likely phishing",
  suspicious: "Suspicious: be careful",
  low: "No strong phishing signs found",
  cant_assess: "Can't assess",
};

export const BAND_ORDER: Band[] = ["high", "suspicious", "low", "cant_assess"];
