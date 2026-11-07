import { describe, expect, it } from "vitest";
import { ringDefaults, ruleDefaults, ruleTemplates, weekOrder } from "./updateDefaults";

describe("update defaults", () => {
  it("turns the settings into the ring form's values", () => {
    const r = ringDefaults({ ring_restart: "deadline", active_start: "07:30", active_end: "18:00", restart_notify_minutes: 5, restart_deadline_hours: 48, window_enabled: true, window_days: ["saturday", "sunday"], window_start: "22:00", window_end: "05:00" });
    expect(r).toMatchObject({ restart: "deadline", activeStart: 450, activeEnd: 1080, notify: 5, deadline: 48, useWindow: true, days: ["6", "0"], windowStart: 1320, windowMinutes: 420 });
  });
  it("falls back to the built-in defaults when nothing is set", () => {
    expect(ringDefaults(undefined)).toMatchObject({ restart: "never", activeStart: 480, activeEnd: 1020, useWindow: false, windowMinutes: 420 });
    expect(ruleDefaults(undefined)).toEqual({ drivers: false, delay: 0 });
    expect(ruleTemplates(undefined)).toEqual([]);
  });
  it("reads templates", () => {
    const t = ruleTemplates({ rule_templates: [{ id: "a", name: "Security", classifications: ["Security Updates"], severities: [], include_drivers: false, delay_days: 7 }] });
    expect(t[0]).toEqual({ id: "a", name: "Security", classifications: ["Security Updates"], severities: [], include_drivers: false, delay_days: 7 });
  });
});

describe("week order", () => {
  it("starts on the chosen day", () => {
    expect(weekOrder("monday")).toEqual([1, 2, 3, 4, 5, 6, 0]);
    expect(weekOrder("sunday")).toEqual([0, 1, 2, 3, 4, 5, 6]);
    expect(weekOrder("saturday")).toEqual([6, 0, 1, 2, 3, 4, 5]);
    expect(weekOrder(undefined)).toEqual([1, 2, 3, 4, 5, 6, 0]);
  });
});
