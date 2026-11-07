import { CopyButton } from "@mantine/core";
import { Check, Copy } from "./icons";
import { IconButton } from "./IconButton";

/** A command or token that people copy: a monospaced block (a pre) with a copy button that says "Copied" for a moment. */
export function CommandBlock({ value, label = "Copy" }: { value: string; label?: string }) {
  return (
    <div style={{ display: "flex", gap: "var(--lp-space-2)", alignItems: "flex-start" }}>
      <pre
        tabIndex={0} // NOSONAR: a scrollable command block must be reachable by keyboard (WCAG 2.1.1)
        style={{
          flex: 1,
          minWidth: 0,
          margin: 0,
          padding: "var(--lp-space-3)",
          background: "var(--lp-surface-sunken)",
          border: "1px solid var(--lp-border)",
          borderRadius: "var(--lp-radius-md)",
          color: "var(--lp-text)",
          fontFamily: "var(--lp-font-mono)",
          fontSize: "var(--lp-text-sm)",
          whiteSpace: "pre-wrap",
          wordBreak: "break-all",
        }}
      >
        {value}
      </pre>
      <CopyButton value={value}>
        {({ copied, copy }) => <IconButton label={copied ? "Copied" : label} icon={copied ? <Check size={16} aria-hidden /> : <Copy size={16} aria-hidden />} variant="default" onClick={copy} />}
      </CopyButton>
    </div>
  );
}
