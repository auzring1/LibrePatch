import { Tooltip } from "@mantine/core";
import { Check, Clock, EyeOff, Close } from "./icons";
import { StatusPill } from "./StatusPill";

/** An update's approval state: approved / declined / hidden / pending, with who decided in the tooltip. */
export function DecisionPill({ decision, source, size }: { decision: string; source?: string; size?: "sm" | "md" }) {
  const map = {
    approved: { kind: "success", label: "Approved", icon: Check },
    declined: { kind: "neutral", label: "Declined", icon: Close },
    hidden: { kind: "neutral", label: "Hidden", icon: EyeOff },
    "": { kind: "info", label: "Pending", icon: Clock },
  } as const;
  const m = map[decision as keyof typeof map] ?? map[""];
  return (
    <Tooltip label={source === "rule" ? "Approved automatically by a rule" : decision ? "Decided by an administrator" : "Waiting for a decision"}>
      <span>
        <StatusPill kind={m.kind} icon={m.icon} size={size}>
          {m.label}
          {source === "rule" ? " (rule)" : ""}
        </StatusPill>
      </span>
    </Tooltip>
  );
}
