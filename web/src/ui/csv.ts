/** Neutralizes spreadsheet formula injection: a cell starting with = + - @ tab or CR is prefixed with an apostrophe. */
export function csvSafe(s: string): string {
  return s !== "" && "=+-@\t\r".includes(s[0]!) ? `'${s}` : s;
}

const cell = (v: unknown): string => {
  if (v === null || v === undefined) return "";
  if (v instanceof Date) return v.toISOString();
  if (typeof v === "boolean") return v ? "yes" : "no";
  return String(v);
};

/** RFC 4180 CSV with a UTF-8 BOM (so Excel reads accents) and formula-injection protection. */
export function toCsv(header: string[], rows: unknown[][]): string {
  const esc = (v: unknown) => {
    const s = csvSafe(cell(v));
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return "﻿" + [header, ...rows].map((r) => r.map(esc).join(",")).join("\r\n") + "\r\n";
}

/** Saves text as a file in the browser (no network involved). */
export function downloadText(name: string, text: string, type = "text/csv;charset=utf-8") {
  const a = document.createElement("a");
  const url = URL.createObjectURL(new Blob([text], { type }));
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
