import { createContext, useCallback, useContext, useLayoutEffect, useMemo, useState, type ReactNode } from "react";
import { MantineProvider } from "@mantine/core";
import { useMediaQuery } from "@mantine/hooks";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type Preferences } from "../api/client";
import { useSession } from "../api/session";
import { useEffective } from "../settings/useEffective";
import { useBranding } from "../branding/BrandingProvider";
import { buildTheme } from "../branding/theme";
import { applyAccent } from "./accent";
import { offeredThemes, resolveTheme, SYSTEM_THEME, THEMES, theme as findTheme, type ThemeDef } from "./themes";

type Prefs = Preferences;
export type Density = "comfortable" | "compact";
export interface SavedView {
  id: string;
  name: string;
  state: Record<string, unknown>;
}

const THEME_KEY = "lp-theme";
const DENSITY_KEY = "lp-density";
const read = (k: string) => {
  try {
    return window.localStorage.getItem(k) ?? "";
  } catch {
    return "";
  }
};
const write = (k: string, v: string) => {
  try {
    if (v) window.localStorage.setItem(k, v);
    else window.localStorage.removeItem(k);
  } catch {
    /* private mode: the account copy still works */
  }
};

export interface Appearance {
  /** The person's own choice: "" (the organization default), "system" or a theme id. */
  choice: string;
  setChoice: (id: string) => void;
  /** The theme in effect. */
  theme: ThemeDef;
  /** Themes the person may pick (the organization's list, or all). */
  offered: ThemeDef[];
  /** Whether "follow the device" is offered. */
  systemOffered: boolean;
  density: Density;
  setDensity: (d: Density) => void;
  /** Saved table views (kept on the account). */
  views: (tableId: string) => SavedView[];
  saveViews: (tableId: string, views: SavedView[]) => void;
}

const Ctx = createContext<Appearance | null>(null);

export function useAppearance(): Appearance {
  const a = useContext(Ctx);
  if (!a) throw new Error("useAppearance needs AppearanceProvider");
  return a;
}

/**
 * Owns the look of the console: applies the chosen theme (data-theme on the root element), layers the branding
 * accent on it, hands Mantine its color scheme, and keeps the person's choice on their account.
 */
export function AppearanceProvider({ nonce, children }: { nonce: string; children: ReactNode }) {
  const brand = useBranding();
  const { session } = useSession();
  const qc = useQueryClient();
  const systemDark = useMediaQuery("(prefers-color-scheme: dark)", false, { getInitialValueInEffect: false }) ?? false;

  const prefsQ = useQuery({ queryKey: ["preferences"], queryFn: () => api<Prefs>("GET", "/me/preferences"), enabled: !!session, staleTime: 5 * 60_000 });
  const prefs = prefsQ.data;

  // Until the account's copy arrives (and when signed out) the choice cached on this device is used.
  const [local, setLocal] = useState({ theme: read(THEME_KEY), density: read(DENSITY_KEY) });
  const accountTheme = prefs ? (prefs.theme ?? "") : undefined;
  const accountDensity = prefs ? (prefs.density ?? "") : undefined;
  const choice = accountTheme !== undefined ? accountTheme : local.theme;
  const densityChoice = accountDensity !== undefined ? accountDensity : local.density;
  const orgDensity = useEffective().data?.appearance.default_density;
  const density: Density = (densityChoice || orgDensity) === "compact" ? "compact" : "comfortable";

  const exists = useCallback((id: string) => !!findTheme(id), []);
  const effective = useMemo(
    () => findTheme(resolveTheme({ choice, orgDefault: brand.default_theme, allowed: brand.allowed_themes, systemDark, exists })) ?? THEMES[0]!,
    [choice, brand.default_theme, brand.allowed_themes, systemDark, exists],
  );

  useLayoutEffect(() => {
    const root = document.documentElement;
    root.setAttribute("data-theme", effective.id);
    root.setAttribute("data-density", density);
    applyAccent(root, effective, brand.accent_color, brand.secondary_color);
    if (accountTheme !== undefined) write(THEME_KEY, accountTheme);
    if (accountDensity !== undefined) write(DENSITY_KEY, accountDensity);
  }, [effective, density, brand.accent_color, brand.secondary_color, accountTheme, accountDensity]);

  const save = useMutation({
    mutationFn: (next: Prefs) => api<Prefs>("PUT", "/me/preferences", next),
    onMutate: async (next) => {
      await qc.cancelQueries({ queryKey: ["preferences"] });
      const prev = qc.getQueryData<Prefs>(["preferences"]);
      qc.setQueryData(["preferences"], next);
      return { prev };
    },
    onError: (_e, _n, ctx) => ctx?.prev && qc.setQueryData(["preferences"], ctx.prev),
    onSuccess: (saved) => qc.setQueryData(["preferences"], saved),
  });
  const current = (): Prefs => ({ ...(prefs ?? {}), theme: choice, density: densityChoice as Prefs["density"], views: prefs?.views ?? {} });

  const value = useMemo<Appearance>(
    () => ({
      choice,
      setChoice: (id) => {
        write(THEME_KEY, id);
        setLocal((l) => ({ ...l, theme: id }));
        if (session) save.mutate({ ...current(), theme: id });
      },
      theme: effective,
      offered: offeredThemes(brand.allowed_themes),
      systemOffered: brand.allowed_themes.length === 0 || brand.allowed_themes.includes(SYSTEM_THEME),
      density,
      setDensity: (d) => {
        write(DENSITY_KEY, d);
        setLocal((l) => ({ ...l, density: d }));
        if (session) save.mutate({ ...current(), density: d });
      },
      views: (tableId) => ((prefs?.views ?? {})[tableId] as SavedView[] | undefined) ?? [],
      saveViews: (tableId, views) => {
        if (session) save.mutate({ ...current(), views: { ...(prefs?.views ?? {}), [tableId]: views } });
      },
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [choice, effective, brand.allowed_themes, density, session, prefs],
  );

  const mantineTheme = useMemo(() => buildTheme({ accent: brand.accent_color, secondary: brand.secondary_color }), [brand.accent_color, brand.secondary_color]);
  return (
    <Ctx.Provider value={value}>
      <MantineProvider theme={mantineTheme} forceColorScheme={effective.scheme} getStyleNonce={() => nonce}>
        {children}
      </MantineProvider>
    </Ctx.Provider>
  );
}

/** Clears what this device remembers about the signed-in person (call when signing out). */
export function forgetLocalAppearance() {
  write(THEME_KEY, "");
  write(DENSITY_KEY, "");
}
