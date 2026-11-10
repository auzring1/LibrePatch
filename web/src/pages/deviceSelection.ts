/** What the Devices list's bulk bar acts on. Every row can be selected; each action takes only the devices it applies to. */
export interface SelectedDevice {
  id: string;
  status: string;
}

export function bulkTargets<T extends SelectedDevice>(rows: readonly T[]): { active: T[]; revoked: T[]; others: number } {
  const active = rows.filter((r) => r.status === "active");
  const revoked = rows.filter((r) => r.status === "revoked");
  return { active, revoked, others: rows.length - revoked.length };
}
