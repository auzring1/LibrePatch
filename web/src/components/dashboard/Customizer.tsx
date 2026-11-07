import { Button, Drawer, Switch } from "@mantine/core";
import { Icons, IconButton } from "../../ui";
import { WIDGET_TITLES, type WidgetId } from "./layout";

interface Props {
  opened: boolean;
  onClose: () => void;
  /** Widgets this person can see, in display order. */
  items: WidgetId[];
  hidden: string[];
  disabled?: boolean;
  onToggle: (id: WidgetId, visible: boolean) => void;
  onMove: (id: WidgetId, dir: -1 | 1) => void;
  onReset: () => void;
}

/** The panel for showing, hiding and reordering widgets. Everything is a switch or a button, so it works from the keyboard. */
export function Customizer({ opened, onClose, items, hidden, disabled, onToggle, onMove, onReset }: Props) {
  return (
    <Drawer opened={opened} onClose={onClose} title="Customize dashboard" position="right" size="md">
      <p style={{ marginTop: 0, color: "var(--lp-text-muted)", fontSize: "var(--lp-text-sm)" }}>
        Choose which widgets to show and in which order. Changes are saved to your account and apply on every device you sign in on.
      </p>
      <ol className="lp-dash-custom" aria-label="Dashboard widgets">
        {items.map((id, i) => {
          const title = WIDGET_TITLES[id];
          const shown = !hidden.includes(id);
          return (
            <li key={id}>
              <Switch label={title} checked={shown} disabled={disabled} onChange={(e) => onToggle(id, e.currentTarget.checked)} />
              <span className="lp-dash-custom__move">
                <IconButton label={`Move ${title} up`} icon={<Icons.ArrowUp size={16} aria-hidden="true" />} disabled={disabled || i === 0} onClick={() => onMove(id, -1)} />
                <IconButton label={`Move ${title} down`} icon={<Icons.ArrowDown size={16} aria-hidden="true" />} disabled={disabled || i === items.length - 1} onClick={() => onMove(id, 1)} />
              </span>
            </li>
          );
        })}
      </ol>
      <div style={{ marginTop: "var(--lp-space-4)", display: "flex", gap: "var(--lp-space-2)", justifyContent: "space-between" }}>
        <Button variant="default" leftSection={<Icons.Restore size={16} aria-hidden="true" />} onClick={onReset} disabled={disabled}>
          Reset to default
        </Button>
        <Button onClick={onClose}>Done</Button>
      </div>
    </Drawer>
  );
}
