import { describe, expect, it } from "vitest";
import { availableAutomationTabs, resolveAutomationTab } from "./automations";

const both = { software: true, windows: true };

describe("automation tabs", () => {
  it("lists Software first and hides Windows when it is not available", () => {
    expect(availableAutomationTabs(both)).toEqual(["software", "windows"]);
    expect(availableAutomationTabs({ software: true, windows: false })).toEqual(["software"]);
    expect(availableAutomationTabs({ software: false, windows: true })).toEqual(["windows"]);
    expect(availableAutomationTabs({ software: false, windows: false })).toEqual([]);
  });

  it("opens Software by default", () => {
    expect(resolveAutomationTab(null, both)).toBe("software");
    expect(resolveAutomationTab("", both)).toBe("software");
    expect(resolveAutomationTab("nonsense", both)).toBe("software");
  });

  it("opens the tab that was asked for, by name or by an old name", () => {
    expect(resolveAutomationTab("windows", both)).toBe("windows");
    expect(resolveAutomationTab("WINDOWS", both)).toBe("windows");
    expect(resolveAutomationTab("update-policy", both)).toBe("windows");
    expect(resolveAutomationTab("policies", both)).toBe("software");
  });

  it("falls back to Software when Windows updates are switched off", () => {
    const off = { software: true, windows: false };
    expect(resolveAutomationTab("windows", off)).toBe("software");
    expect(resolveAutomationTab("update-policy", off)).toBe("software");
  });

  it("falls back to Windows for a person who can only see that tab", () => {
    expect(resolveAutomationTab("software", { software: false, windows: true })).toBe("windows");
  });
});
