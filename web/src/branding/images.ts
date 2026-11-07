import type { BrandingAssetKind } from "../api/client";

/** The upload rules; the server enforces the same ones (internal/server/branding/image.go) and is the authority. */
export const MAX_IMAGE_BYTES = 512 * 1024;

interface Limits {
  minW: number;
  minH: number;
  maxW: number;
  maxH: number;
  square: boolean;
  hint: string;
}

export const LIMITS: Record<BrandingAssetKind, Limits> = {
  logo_light: { minW: 16, minH: 16, maxW: 1200, maxH: 400, square: false, hint: "PNG or JPEG, up to 1200 × 400 px" },
  logo_dark: { minW: 16, minH: 16, maxW: 1200, maxH: 400, square: false, hint: "PNG or JPEG, up to 1200 × 400 px" },
  report_logo: { minW: 16, minH: 16, maxW: 1200, maxH: 400, square: false, hint: "PNG or JPEG, up to 1200 × 400 px" },
  icon: { minW: 64, minH: 64, maxW: 512, maxH: 512, square: true, hint: "Square PNG or JPEG, 64 to 512 px" },
  favicon: { minW: 16, minH: 16, maxW: 256, maxH: 256, square: true, hint: "Square PNG or JPEG, 16 to 256 px" },
};

export interface LocalImage {
  /** A data: URL, which the page's CSP allows (blob: URLs are not). */
  dataUrl: string;
  width: number;
  height: number;
}

const readAsDataUrl = (file: File) =>
  new Promise<string>((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(String(r.result));
    r.onerror = () => reject(new Error("The file could not be read."));
    r.readAsDataURL(file);
  });

/**
 * Checks a chosen file before it is sent: type, size and dimensions. Throws a message fit to show to the user.
 * SVG is refused on purpose (it can carry scripts).
 */
export async function checkImageFile(file: File, kind: BrandingAssetKind): Promise<LocalImage> {
  if (file.type === "image/svg+xml" || file.name.toLowerCase().endsWith(".svg")) throw new Error("SVG images are not accepted (they can carry scripts). Use a PNG or JPEG.");
  if (file.type !== "image/png" && file.type !== "image/jpeg") throw new Error("Only PNG and JPEG images are accepted.");
  if (file.size > MAX_IMAGE_BYTES) throw new Error(`The image is larger than ${MAX_IMAGE_BYTES / 1024} KB.`);
  const dataUrl = await readAsDataUrl(file);
  const { width, height } = await new Promise<{ width: number; height: number }>((resolve, reject) => {
    const im = new Image();
    im.onload = () => resolve({ width: im.naturalWidth, height: im.naturalHeight });
    im.onerror = () => reject(new Error("The file is not a valid image."));
    im.src = dataUrl;
  });
  const l = LIMITS[kind];
  if (width < l.minW || height < l.minH) throw new Error(`The image is too small: at least ${l.minW} × ${l.minH} pixels.`);
  if (width > l.maxW || height > l.maxH) throw new Error(`The image is too large: at most ${l.maxW} × ${l.maxH} pixels for this slot (it is ${width} × ${height}).`);
  if (l.square && width !== height) throw new Error(`This slot needs a square image (it is ${width} × ${height}).`);
  return { dataUrl, width, height };
}

/** The base64 part of a data URL. */
export const base64Of = (dataUrl: string): string => dataUrl.slice(dataUrl.indexOf(",") + 1);
