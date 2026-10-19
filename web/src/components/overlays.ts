import type { OverlaySource } from "../api/client";
import type { PillKind } from "../ui";

/** How an overlay source is doing, in one pill. A source that is switched off says so first. */
export function overlayStatus(s: Pick<OverlaySource, "enabled" | "status" | "last_error">): { kind: PillKind; label: string; title?: string } {
  if (!s.enabled) return { kind: "neutral", label: "Off" };
  if (s.status === "error") return { kind: "danger", label: "Problem", title: s.last_error || "The last check failed" };
  if (s.status === "new") return { kind: "neutral", label: "Not checked yet" };
  return { kind: "success", label: "In use" };
}

/** Where a source's document comes from. */
export function overlayOrigin(s: Pick<OverlaySource, "kind" | "url">): string {
  if (s.kind !== "url") return "Uploaded file";
  try {
    return new URL(s.url).host;
  } catch {
    return s.url;
  }
}

/** "3 packages, 2 verified". */
export function overlayCounts(s: Pick<OverlaySource, "entries" | "verified_entries">): string {
  const n = s.entries === 1 ? "1 package" : `${s.entries} packages`;
  return s.verified_entries > 0 ? `${n}, ${s.verified_entries} verified` : n;
}

/** True when the text looks like a signed overlay file; the server does the real check, this only catches the wrong file. */
export function looksLikeOverlayFile(text: string): boolean {
  try {
    const j = JSON.parse(text) as { format?: unknown };
    return typeof j === "object" && j !== null && j.format === "librepatch-overlay-bundle/1";
  } catch {
    return false;
  }
}

/** A public key is 64 hexadecimal characters; whitespace around it is ignored. */
export function isPublicKey(s: string): boolean {
  return /^[0-9a-fA-F]{64}$/.test(s.trim());
}
