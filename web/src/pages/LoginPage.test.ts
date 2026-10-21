import { describe, expect, it } from "vitest";
import { ssoMessage } from "./LoginPage";

describe("ssoMessage", () => {
  it("explains each refusal without naming the provider's reason", () => {
    expect(ssoMessage("no_access")).toMatch(/role/);
    expect(ssoMessage("account_exists")).toMatch(/not linked/);
    expect(ssoMessage("disabled")).toMatch(/switched off/);
    expect(ssoMessage("expired")).toMatch(/again/);
    expect(ssoMessage("denied")).toMatch(/cancelled or refused/);
    expect(ssoMessage("unavailable")).toMatch(/password/);
  });
  it("has a general message for anything else, including text that came from the address bar", () => {
    expect(ssoMessage("<script>alert(1)</script>")).toBe(ssoMessage("failed"));
    expect(ssoMessage("")).toBe(ssoMessage("failed"));
  });
});
