import { describe, expect, it } from "vitest";
import { SETTINGS_SECTIONS } from "../ui/nav";
import { toRequest } from "./SectionForm";
import { searchSettings } from "./search";
import { localErrors, newItem, type SettingsField, type SettingsSection } from "./types";

const f = (o: Partial<SettingsField> & { key: string; kind: SettingsField["kind"] }): SettingsField => ({ label: o.key, help: "", effect: "live", ...o });

const section: SettingsSection = {
  id: "notifications",
  label: "Notifications",
  description: "",
  perm: "settings:notifications",
  editable: true,
  fields: [
    f({ key: "smtp_host", kind: "string", label: "Mail server", help: "Host name of your SMTP relay." }),
    f({ key: "smtp_port", kind: "int", min: 1, max: 65535, default: 587 }),
    f({ key: "smtp_password", kind: "secret", label: "Password" }),
    f({
      key: "webhooks",
      kind: "list",
      fields: [f({ key: "id", kind: "string" }), f({ key: "name", kind: "string", required: true, default: "New" }), f({ key: "secret", kind: "secret" }), f({ key: "enabled", kind: "bool", default: true })],
    }),
  ],
};

describe("settings search", () => {
  const pages = SETTINGS_SECTIONS.filter((s) => s.section === "notifications" || s.section === "security");
  it("finds a setting by its label, help text or key words", () => {
    expect(searchSettings([section], pages, "mail server").map((h) => h.label)).toContain("Mail server");
    expect(searchSettings([section], pages, "relay").map((h) => h.label)).toContain("Mail server");
    expect(searchSettings([section], pages, "smtp host").map((h) => h.label)).toContain("Mail server");
  });
  it("links to the section and the field", () => {
    const hit = searchSettings([section], pages, "relay").find((h) => h.label === "Mail server")!;
    expect(hit.to).toBe("/settings/notifications?field=smtp_host");
  });
  it("finds sections by their keywords and ignores sections the person may not open", () => {
    expect(searchSettings([], pages, "smtp").map((h) => h.to)).toContain("/settings/notifications");
    expect(searchSettings([section], [], "mail")).toEqual([]);
  });
  it("needs every word to match", () => {
    expect(searchSettings([section], pages, "mail banana")).toEqual([]);
  });
});

describe("settings form helpers", () => {
  it("checks numbers and required text locally", () => {
    expect(localErrors(section.fields.filter((x) => x.kind !== "secret"), { smtp_host: "", smtp_port: 70000, webhooks: [{ name: "" }] })).toEqual({
      smtp_port: "Enter a number from 1 to 65535.",
      "webhooks[0].name": "This is required.",
    });
    expect(localErrors(section.fields, { smtp_host: "x", smtp_port: 25, webhooks: [] })).toEqual({});
  });
  it("starts a new list item from the defaults, without secrets", () => {
    expect(newItem(section.fields[3]!)).toEqual({ id: "", name: "New", enabled: true });
  });
  it("sends a secret only when one was typed or explicitly removed", () => {
    expect(toRequest(section, { smtp_host: "h", smtp_port: 25, smtp_password: "", webhooks: [] })).not.toHaveProperty("smtp_password");
    expect(toRequest(section, { smtp_host: "h", smtp_port: 25, smtp_password: "pw", webhooks: [] })["smtp_password"]).toBe("pw");
    expect(toRequest(section, { smtp_host: "h", smtp_port: 25, smtp_password: "", __clear_smtp_password: true, webhooks: [] })["smtp_password"]).toBe("");
    const out = toRequest(section, { smtp_host: "h", smtp_port: 25, webhooks: [{ id: "a", name: "x", secret: "" }, { id: "b", name: "y", secret: "s" }] });
    expect((out["webhooks"] as Record<string, unknown>[])[0]).not.toHaveProperty("secret");
    expect((out["webhooks"] as Record<string, unknown>[])[1]!["secret"]).toBe("s");
  });
});
