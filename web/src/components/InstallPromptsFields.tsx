import { Alert, NumberInput, Select, Stack, Text } from "@mantine/core";
import { Link } from "react-router-dom";
import { IN_USE_OPTIONS, RESTART_OPTIONS, needsPrograms, type PromptsForm } from "./prompts";
import { Icons } from "../ui";

/**
 * The optional messages to the signed-in user (D124): what to do when the program being updated is open, and what to do
 * when the installer needs a restart. The default is silent, as before.
 */
export function InstallPromptsFields({
  value,
  onChange,
  programs,
  packageId,
  disabled,
  perApp,
}: {
  value: PromptsForm;
  onChange: (v: PromptsForm) => void;
  /** The package's program names (its override, or the overlay's). */
  programs: string[];
  packageId?: string;
  disabled?: boolean;
  /** For an all-apps policy: there is no single package, so each app uses its own program names (an app without any is installed silently). */
  perApp?: boolean;
}) {
  const set = (patch: Partial<PromptsForm>) => onChange({ ...value, ...patch });
  return (
    <Stack>
      <Select
        label="If the program is open"
        description="Silent installs stay the default. Pick another option only for programs people keep open, such as a browser."
        data={IN_USE_OPTIONS}
        value={value.inUse}
        onChange={(v) => v && set({ inUse: v as PromptsForm["inUse"] })}
        allowDeselect={false}
        disabled={disabled}
      />
      {needsPrograms(value) && perApp && (
        <Text size="sm" c="dimmed">
          Each app uses the program names saved for it (under Overrides on its catalog page). An app that has none is installed silently.
        </Text>
      )}
      {needsPrograms(value) &&
        !perApp &&
        (programs.length === 0 ? (
          <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />}>
            This package has no program names yet, so there is nothing to look for.{" "}
            {packageId ? <Link to={`/catalog/${packageId}`}>Add them under Overrides on its page</Link> : "Add them under Overrides on the package's page"} (for example chrome.exe).
          </Alert>
        ) : (
          <Text size="sm" c="dimmed">
            Looks for: <b>{programs.join(", ")}</b>
          </Text>
        ))}
      {(value.inUse === "ask" || value.inUse === "close") && (
        <NumberInput
          label={value.inUse === "ask" ? "The question stays up for (seconds)" : "Warn the user this long before closing (seconds)"}
          min={30}
          max={3600}
          value={value.askTimeoutS}
          onChange={(v) => set({ askTimeoutS: v })}
          disabled={disabled}
          maw={280}
        />
      )}
      {(value.inUse === "skip" || value.inUse === "ask") && (
        <NumberInput
          label="If it stays open, look again after (minutes)"
          description="The job keeps trying until it expires. This does not use up its retries."
          min={5}
          max={1440}
          value={value.deferMinutes}
          onChange={(v) => set({ deferMinutes: v })}
          disabled={disabled}
          maw={280}
        />
      )}
      <Select
        label="If the installer says a restart is needed"
        description="Only applies when the installer itself asks for a restart. Windows restarts are otherwise left to you."
        data={RESTART_OPTIONS}
        value={value.restart}
        onChange={(v) => v && set({ restart: v as PromptsForm["restart"] })}
        allowDeselect={false}
        disabled={disabled}
      />
      {value.restart !== "none" && (
        <NumberInput label="Restart countdown (minutes)" min={1} max={1440} value={value.restartMinutes} onChange={(v) => set({ restartMinutes: v })} disabled={disabled} maw={280} />
      )}
    </Stack>
  );
}
