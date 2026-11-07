import { Link } from "react-router-dom";
import { Menu } from "@mantine/core";
import { useAppearance } from "../design/AppearanceProvider";
import { SYSTEM_THEME, type ThemeDef } from "../design/themes";
import * as I from "./icons";

/** Three bands of a theme's own colors, drawn from its tokens, so the picker previews each theme faithfully. */
function Swatch({ t }: { t: ThemeDef }) {
  return (
    <span className="lp-swatch" style={{ background: t.tokens["bg"] }} aria-hidden="true">
      <span style={{ background: t.tokens["surface"] }} />
      <span style={{ background: t.tokens["accent"] }} />
    </span>
  );
}

const initials = (name: string) =>
  name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]!.toUpperCase())
    .join("") || "?";

export function UserMenu({ name, email, onSignOut }: { name: string; email: string; onSignOut: () => void }) {
  const { choice, setChoice, offered, systemOffered, density, setDensity, theme } = useAppearance();
  const current = choice || (systemOffered ? SYSTEM_THEME : "");
  return (
    <Menu position="bottom-end" width={270} shadow="md" withinPortal closeOnItemClick={false}>
      <Menu.Target>
        <button type="button" className="lp-usermenu" data-testid="user-menu">
          {/* The name comes from this hidden text, not from an aria-label: a label that leaves out text people can see
              (the initials, the name) fails WCAG 2.5.3. The visible name is hidden from screen readers so it is not read twice. */}
          <span className="lp-visually-hidden">Account menu for {name}</span>
          <span className="lp-avatar" aria-hidden="true">
            {initials(name)}
          </span>
          <span className="lp-topbar__search-wide" style={{ fontWeight: 500 }} aria-hidden="true">
            {name}
          </span>
          <I.ChevronDown size={14} aria-hidden />
        </button>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>
          <div style={{ color: "var(--lp-text)", fontWeight: 600, fontSize: "var(--lp-text-md)" }}>{name}</div>
          <div style={{ color: "var(--lp-text-muted)", fontWeight: 400, textTransform: "none", letterSpacing: 0 }}>{email}</div>
        </Menu.Label>
        <Menu.Item component={Link} to="/account" leftSection={<I.User size={16} aria-hidden />}>
          Account and security
        </Menu.Item>
        <Menu.Divider />
        <Menu.Label>Theme</Menu.Label>
        {systemOffered && (
          <Menu.Item onClick={() => setChoice(SYSTEM_THEME)} aria-current={current === SYSTEM_THEME ? "true" : undefined} leftSection={<I.Laptop size={16} aria-hidden />} rightSection={current === SYSTEM_THEME ? <I.Check size={16} aria-hidden /> : null}>
            Follow my device
          </Menu.Item>
        )}
        {offered.map((t) => (
          <Menu.Item key={t.id} onClick={() => setChoice(t.id)} aria-current={choice === t.id || (!choice && !systemOffered && theme.id === t.id) ? "true" : undefined} leftSection={<Swatch t={t} />} rightSection={choice === t.id ? <I.Check size={16} aria-hidden /> : null}>
            {t.name}
          </Menu.Item>
        ))}
        <Menu.Divider />
        <Menu.Label>Table density</Menu.Label>
        <Menu.Item onClick={() => setDensity("comfortable")} aria-current={density === "comfortable" ? "true" : undefined} leftSection={<I.DensityComfortable size={16} aria-hidden />} rightSection={density === "comfortable" ? <I.Check size={16} aria-hidden /> : null}>
          Comfortable
        </Menu.Item>
        <Menu.Item onClick={() => setDensity("compact")} aria-current={density === "compact" ? "true" : undefined} leftSection={<I.DensityCompact size={16} aria-hidden />} rightSection={density === "compact" ? <I.Check size={16} aria-hidden /> : null}>
          Compact
        </Menu.Item>
        <Menu.Divider />
        <Menu.Item onClick={onSignOut} color="red" leftSection={<I.SignOut size={16} aria-hidden />} closeMenuOnClick>
          Sign out
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}
