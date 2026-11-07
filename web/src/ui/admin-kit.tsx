import type { CSSProperties, ReactNode } from "react";
import { BrandMark, useBranding } from "../branding/BrandingProvider";
import type { ThemeDef } from "../design/themes";
import "./admin-kit.css";

/** A definition list: label on the left, value on the right (stacked on a phone). */
export function KeyValue({ items, label }: { items: { label: string; value: ReactNode; testId?: string }[]; label?: string }) {
  return (
    <dl className="lp-kv" aria-label={label}>
      {items.map((i) => (
        <div key={i.label}>
          <dt>{i.label}</dt>
          <dd data-testid={i.testId}>{i.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** The buttons of a table's last column; they stay in view when the table scrolls sideways. */
export function RowButtons({ children }: { children: ReactNode }) {
  return <span className="lp-sticky-actions">{children}</span>;
}

/** A heading over content that has no card of its own (a table with its own frame). One level below the page title. */
export function Section({ title, description, actions, children }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="lp-section">
      <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: "var(--lp-space-3)", flexWrap: "wrap" }}>
        <div>
          <h2 className="lp-section__title">{title}</h2>
          {description && <p className="lp-section__desc">{description}</p>}
        </div>
        {actions}
      </div>
      <div style={{ marginTop: "var(--lp-space-3)" }}>{children}</div>
    </section>
  );
}

/** Three stripes (page, surface, accent) taken from a theme's own tokens, so a theme can be recognised at a glance. */
export function ThemeSwatch({ theme }: { theme: ThemeDef }) {
  const t = theme.tokens;
  return (
    <span className="lp-theme-swatch" aria-hidden="true">
      <span style={{ background: t["bg"] }} />
      <span style={{ background: t["surface"] }} />
      <span style={{ background: t["accent"] }} />
    </span>
  );
}

/** Full-page, centered card on the themed background (sign-in and first-run setup). */
export function AuthShell({ children, below, width = 440 }: { children: ReactNode; below?: ReactNode; width?: number }) {
  const style = { "--lp-auth-w": `${width}px` } as CSSProperties;
  return (
    <main className="lp-auth" style={style}>
      <div className="lp-auth__card">{children}</div>
      {below && <div className="lp-auth__below">{below}</div>}
    </main>
  );
}

/** The deployment's logo, or a plain mark with the product's initial while no image is configured. */
export function AuthBrand({ height = 48 }: { height?: number }) {
  const b = useBranding();
  const hasImage = !!(b.assets.logo_light || b.assets.logo_dark || b.assets.icon);
  if (hasImage) return <BrandMark height={height} />;
  return (
    <span className="lp-auth__mark" aria-hidden="true">
      {(b.product_name || "R").trim().charAt(0).toUpperCase()}
    </span>
  );
}
