import { describe, expect, it } from "vitest";
import { masterKeyFile } from "./masterKeyFile";

describe("masterKeyFile", () => {
  const k = { key: "a1b2c3d4-e5f6a7b8-c9d0e1f2-a3b4c5d6-e7f8a9b0-c1d2e3f4-a5b6c7d8-e9f0a1b2", key_id: "0f1e2d3c", generated_at: "2026-10-16T09:00:00Z" };
  const text = masterKeyFile("LibrePatch", k);

  it("holds the key, its id and the date, so the file alone is enough to restore from", () => {
    expect(text).toContain(`Master key: ${k.key}`);
    expect(text).toContain("Key id:     0f1e2d3c");
    expect(text).toContain("2026-10-16T09:00:00Z");
  });

  it("says what the key is for and where not to keep it", () => {
    expect(text).toContain("LibrePatch master key");
    expect(text).toContain("NOT on the server");
    expect(text).toContain("set-master-key");
  });
});
