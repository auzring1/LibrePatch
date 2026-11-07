import { useMemo, useState, type CSSProperties } from "react";
import { Select, Stack, Text } from "@mantine/core";
import { useMediaQuery } from "@mantine/hooks";
import type { BrandingSettings, BrandingView } from "../api/client";
import { PRODUCT_NAME } from "../brand.generated";
import { deriveAccent, deriveSecondary } from "../design/accent";
import { resolveTheme, THEMES, theme as findTheme } from "../design/themes";
import { ThemeSwatch } from "../ui/admin-kit";
import { DARK_SURFACE, isHexColor, WHITE } from "./contrast";

interface Props {
  draft: BrandingSettings;
  view: BrandingView;
}

/**
 * A faithful sketch of the top bar and sign-in page with the values being edited. It is drawn with the tokens of the
 * previewed theme (the organization's default theme unless another is picked) and the accent derived for that theme
 * exactly as the console does it, so a color can be judged before it is saved, on any theme.
 */
export function BrandPreview({ draft, view }: Props) {
  const systemDark = useMediaQuery("(prefers-color-scheme: dark)", false) ?? false;
  const defaultId = resolveTheme({ choice: "", orgDefault: draft.default_theme ?? "", allowed: draft.allowed_themes ?? [], systemDark, exists: (id) => !!findTheme(id) });
  // A theme picked here only counts while the default it was picked against stays the same.
  const [pick, setPick] = useState<{ against: string; id: string } | null>(null);
  const themeId = pick && pick.against === defaultId ? pick.id : defaultId;
  const t = findTheme(themeId) ?? THEMES[0]!;

  const accent = isHexColor(draft.accent_color ?? "") ? draft.accent_color!.toLowerCase() : "";
  const secondary = isHexColor(draft.secondary_color ?? "") ? draft.secondary_color!.toLowerCase() : "";
  const style = useMemo(() => {
    const v: Record<string, string> = { colorScheme: t.scheme };
    for (const [k, val] of Object.entries(t.tokens)) v[`--lp-${k}`] = val;
    if (accent) {
      const d = deriveAccent(accent, t);
      v["--lp-accent"] = d.accent;
      v["--lp-on-accent"] = d.onAccent;
      v["--lp-accent-text"] = d.accentText;
      v["--lp-accent-subtle"] = d.subtle;
      v["--lp-accent-subtle-text"] = d.subtleText;
      v["--lp-accent-border"] = d.border;
    }
    if (secondary) v["--lp-secondary"] = deriveSecondary(secondary, t);
    return v as CSSProperties;
  }, [t, accent, secondary]);

  const product = (draft.product_name ?? "").trim() || view.defaults.product_name || PRODUCT_NAME;
  const org = (draft.org_name ?? "").trim();
  const dark = t.scheme === "dark";
  const logoRef = dark ? (view.assets.logo_dark ?? view.assets.logo_light) : (view.assets.logo_light ?? view.assets.logo_dark);
  const needsChip = dark ? !view.assets.logo_dark && !!view.assets.logo_light : !view.assets.logo_light && !!view.assets.logo_dark;
  const mark = (h: number) => {
    const ref = logoRef ?? view.assets.icon;
    if (!ref) return null;
    const img = <img src={ref.url} alt="" style={{ height: h, width: "auto", maxWidth: 200, display: "block" }} />;
    // A logo made for the other kind of background sits on a chip of that background so it stays readable.
    return needsChip && logoRef ? (
      <div className="lp-preview__chip" style={{ background: dark ? WHITE : DARK_SURFACE }}>
        {img}
      </div>
    ) : (
      img
    );
  };
  const support = [draft.support_email, draft.support_phone, draft.support_url ? "Support site" : ""].filter(Boolean).join(" · ");

  return (
    <Stack gap="sm" data-testid="brand-preview">
      <Select
        label="Preview theme"
        size="xs"
        data={THEMES.map((x) => ({ value: x.id, label: x.name }))}
        value={t.id}
        onChange={(v) => v && setPick({ against: defaultId, id: v })}
        allowDeselect={false}
        leftSection={<ThemeSwatch theme={t} />}
        leftSectionWidth={50}
        renderOption={({ option }) => {
          const x = findTheme(option.value);
          return (
            <span className="lp-theme-option">
              {x && <ThemeSwatch theme={x} />}
              {option.label}
              {option.value === defaultId ? " (default)" : ""}
            </span>
          );
        }}
      />
      <div className="lp-preview" style={style}>
        <div className="lp-preview__bar">
          {mark(28)}
          <strong data-testid="preview-product">{product}</strong>
          {org && (
            <span data-testid="preview-org" className="lp-preview__muted" style={{ fontSize: 13 }}>
              {org}
            </span>
          )}
          <span className="lp-preview__bar-link">Sign out</span>
        </div>
        <div className="lp-preview__body">
          <div className="lp-preview__card">
            {mark(36)}
            <div style={{ fontSize: 18, fontWeight: 700 }} data-testid="preview-headline">
              {(draft.login_headline ?? "").trim() || `Sign in to ${product}`}
            </div>
            {org && (
              <div className="lp-preview__muted" style={{ fontSize: 12 }}>
                {org}
              </div>
            )}
            {draft.login_message && <div style={{ fontSize: 13, whiteSpace: "pre-line" }}>{draft.login_message}</div>}
            <div className="lp-preview__field" />
            <div className="lp-preview__field" />
            <div className="lp-preview__button">Continue</div>
            <div className="lp-preview__link" style={{ fontSize: 12 }}>
              Use a recovery code instead
            </div>
          </div>
          {draft.login_footer && (
            <div className="lp-preview__muted" style={{ fontSize: 11, textAlign: "center", whiteSpace: "pre-line", maxWidth: 320 }} data-testid="preview-footer">
              {draft.login_footer}
            </div>
          )}
          {support && (
            <div className="lp-preview__link" style={{ fontSize: 11, textAlign: "center" }} data-testid="preview-support">
              Need help? {support}
            </div>
          )}
        </div>
      </div>
      <Text size="xs" c="dimmed">
        Preview only. Images show what is stored; texts and colors update as you type, and the colors are adapted to each theme the way the console does it.
      </Text>
    </Stack>
  );
}
