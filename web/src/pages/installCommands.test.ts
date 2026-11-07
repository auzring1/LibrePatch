import { describe, expect, it } from "vitest";
import { commandText, fileSize } from "./installCommands";

describe("commandText", () => {
  it("is the one-liner when the server has the installer, and never more than one line", () => {
    const oneLiner = 'cmd /s /c "curl.exe -fL -o %SystemRoot%\\Temp\\a.msi https://x/download/a.msi && start /wait msiexec /i %SystemRoot%\\Temp\\a.msi /qn & del /q %SystemRoot%\\Temp\\a.msi 2>nul"';
    const text = commandText({ one_liner: oneLiner, download: "curl.exe -L -o a.msi https://x/download/a.msi", command: "msiexec /i a.msi /qn" });
    expect(text).toBe(oneLiner);
    expect(text).not.toContain("\n");
  });

  it("is the plain install command while the server does not have the file", () => {
    expect(commandText({ one_liner: "", download: "", command: "librepatch-agent.exe install --server h:8443 --token LP1.x" })).toBe("librepatch-agent.exe install --server h:8443 --token LP1.x");
  });
});

describe("fileSize", () => {
  it("reads like a download", () => {
    expect(fileSize(14_900_000)).toBe("14.2 MB");
    expect(fileSize(300)).toBe("1 KB");
    expect(fileSize(51_200)).toBe("50 KB");
    expect(fileSize(0)).toBe("");
    expect(fileSize(NaN)).toBe("");
  });
});
