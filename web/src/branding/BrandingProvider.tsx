import { createContext, useContext, useEffect, type ReactNode } from "react";
import { Box, useComputedColorScheme } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { api, type PublicBranding } from "../api/client";
import { PRODUCT_NAME } from "../brand.generated";
import { DEFAULT_ACCENT } from "./contrast";

/** What an installation shows before an administrator has configured anything. */
export const STOCK_BRANDING: PublicBranding = {
  product_name: PRODUCT_NAME,
  org_name: "",
  title: PRODUCT_NAME,
  accent_color: DEFAULT_ACCENT,
  secondary_color: "",
  login_headline: "",
  login_message: "",
  login_footer: "",
  support: {},
  default_theme: "",
  allowed_themes: [],
  assets: {},
  version: "",
};

/** The branding the server inlined into the page, so the first paint is already branded. */
function inlined(): PublicBranding | undefined {
  try {
    const raw = document.getElementById("branding-data")?.textContent;
    if (!raw) return undefined;
    const b = JSON.parse(raw) as Partial<PublicBranding>;
    if (typeof b.product_name !== "string" || typeof b.accent_color !== "string") return undefined;
    return { ...STOCK_BRANDING, ...b, support: b.support ?? {}, assets: b.assets ?? {} } as PublicBranding;
  } catch {
    return undefined;
  }
}

const Ctx = createContext<PublicBranding>(STOCK_BRANDING);

export const useBranding = (): PublicBranding => useContext(Ctx);

/** Loads the public branding. The theme and the accent layered on it are applied by AppearanceProvider. */
export function BrandingProvider({ children }: { children: ReactNode }) {
  const q = useQuery({
    queryKey: ["branding"],
    queryFn: () => api<PublicBranding>("GET", "/branding"),
    initialData: inlined,
    staleTime: 60_000,
  });
  const b = q.data ?? STOCK_BRANDING;
  return <Ctx.Provider value={b}>{children}</Ctx.Provider>;
}

/** Sets the tab title to "<page> · <organization> · <product>" (or just the branded title). */
export function useDocumentTitle(page?: string) {
  const { title } = useBranding();
  useEffect(() => {
    document.title = page ? `${page} · ${title}` : title;
  }, [page, title]);
}

interface MarkProps {
  /** Height in pixels. */
  height?: number;
  /** Fall back to the square icon when there is no logo. */
  allowIcon?: boolean;
}

/**
 * The deployment's logo for the current color scheme. A logo made for the other background is shown on a small
 * matching chip so it stays readable. Renders nothing when no image is configured.
 */
export function BrandMark({ height = 32, allowIcon = true }: MarkProps) {
  const b = useBranding();
  const scheme = useComputedColorScheme("light");
  const alt = `${b.org_name || b.product_name} logo`;
  const light = b.assets.logo_light;
  const dark = b.assets.logo_dark;
  const icon = allowIcon ? b.assets.icon : undefined;
  const img = (ref: { url: string; width: number; height: number }, rounded = false) => (
    <img src={ref.url} alt={alt} width={ref.width} height={ref.height} style={{ height, width: "auto", maxWidth: 240, display: "block", borderRadius: rounded ? 6 : 0 }} />
  );
  const chip = (bg: string, inner: ReactNode) => (
    <Box data-testid="brand-chip" style={{ background: bg, padding: 4, borderRadius: 6, lineHeight: 0 }}>
      {inner}
    </Box>
  );
  if (scheme === "dark") {
    if (dark) return img(dark);
    if (light) return chip("var(--lp-surface-raised)", img(light));
  } else {
    if (light) return img(light);
    if (dark) return chip("var(--lp-surface-raised)", img(dark));
  }
  return icon ? img(icon, true) : null;
}
