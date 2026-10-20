import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Alert, Button, ColorInput, FileButton, Group, Stack, Text, TextInput, Textarea } from "@mantine/core";
import {
  api,
  ApiError,
  errorMessage,
  uploadBrandingAsset,
  type BrandingAssetKind,
  type BrandingSettings,
  type BrandingView,
} from "../api/client";
import { useSession } from "../api/session";
import { BrandPreview } from "../branding/BrandPreview";
import { ACCENT_SWATCHES, checks, colorProblems, DARK_SURFACE, DEFAULT_ACCENT, SECONDARY_SWATCHES, WHITE } from "../branding/contrast";
import { checkImageFile, LIMITS } from "../branding/images";
import { Card, Icons, Skel, StatusPill, toast, useConfirm } from "../ui";

/** `surface` is what the preview of the slot sits on: a fixed light or dark surface where the image is made for one. */
const SLOTS: { kind: BrandingAssetKind; label: string; help: string; surface?: "light" | "dark" }[] = [
  { kind: "logo_light", label: "Logo for light backgrounds", help: "Shown in the top bar and on the sign-in page in the light theme.", surface: "light" },
  { kind: "logo_dark", label: "Logo for dark backgrounds", help: "Used in the dark theme. Without it the light logo is shown on a light chip.", surface: "dark" },
  { kind: "icon", label: "Square icon", help: "Shown instead of the logo when no logo is set." },
  { kind: "favicon", label: "Favicon", help: "The small icon in the browser tab." },
  { kind: "report_logo", label: "Report and email logo", help: "Printed at the top of exported reports and used in emails. Falls back to the light logo.", surface: "light" },
];

const EMPTY: BrandingSettings = {
  org_name: "",
  product_name: "",
  accent_color: "",
  secondary_color: "",
  login_headline: "",
  login_message: "",
  login_footer: "",
  support_email: "",
  support_phone: "",
  support_url: "",
  report_footer: "",
  default_theme: "",
  allowed_themes: [],
};

const norm = (s: BrandingSettings): BrandingSettings => ({ ...EMPTY, ...s, default_theme: s.default_theme ?? "", allowed_themes: s.allowed_themes ?? [] });

export function BrandingPage() {
  const { can } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const q = useQuery({ queryKey: ["branding-admin"], queryFn: () => api<BrandingView>("GET", "/settings/branding"), enabled: can("branding:write") });
  const [draft, setDraft] = useState<BrandingSettings>(EMPTY);
  const [serverErrors, setServerErrors] = useState<Record<string, string>>({});
  const loaded = useRef("");

  // Take the stored settings into the form when they first load and after every save, but never overwrite edits in progress.
  useEffect(() => {
    if (!q.data) return;
    const key = JSON.stringify(q.data.settings);
    if (loaded.current !== key) {
      loaded.current = key;
      setDraft(norm(q.data.settings));
    }
  }, [q.data]);

  const accept = (v: BrandingView) => {
    qc.setQueryData(["branding-admin"], v);
    qc.setQueryData(["branding"], v.resolved); // the console re-themes at once
  };

  const save = useMutation({
    mutationFn: () => api<BrandingView>("PUT", "/settings/branding", draft),
    onSuccess: (v) => {
      accept(v);
      setServerErrors({});
      toast.success("Branding saved.");
    },
    onError: (e) => {
      if (e instanceof ApiError && e.code === "invalid_branding") setServerErrors(e.fields);
      else toast.error(errorMessage(e));
    },
  });
  const reset = useMutation({
    mutationFn: () => api<BrandingView>("POST", "/settings/branding/reset", {}),
    onSuccess: (v) => {
      accept(v);
      loaded.current = JSON.stringify(v.settings);
      setDraft(norm(v.settings));
      setServerErrors({});
      toast.success("Branding reset to the defaults.");
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  const problems = useMemo(() => colorProblems(draft.accent_color ?? "", draft.secondary_color ?? ""), [draft.accent_color, draft.secondary_color]);
  const liveChecks = useMemo(() => {
    const p = colorProblems(draft.accent_color ?? "", draft.secondary_color ?? "");
    return p.accent?.startsWith("Use a") || p.secondary?.startsWith("Use a") ? [] : checks(draft.accent_color ?? "", draft.secondary_color ?? "");
  }, [draft.accent_color, draft.secondary_color]);

  if (!can("branding:write")) {
    return (
      <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />}>
        Only administrators can change branding.
      </Alert>
    );
  }
  if (q.isLoading) {
    return (
      <Card>
        <div role="status" aria-label="Loading" style={{ display: "grid", gap: "var(--lp-space-3)" }}>
          <Skel w="30%" h={16} />
          <Skel h={36} />
          <Skel h={36} />
          <Skel w="60%" h={12} />
        </div>
      </Card>
    );
  }
  if (q.error || !q.data) {
    return (
      <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
        {errorMessage(q.error)}
      </Alert>
    );
  }
  const view = q.data;
  const dirty = JSON.stringify(norm(draft)) !== JSON.stringify(norm(view.settings));
  const blocked = !!problems.accent || !!problems.secondary;
  const set = (k: keyof BrandingSettings) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setDraft({ ...draft, [k]: e.currentTarget.value });
    if (serverErrors[k]) setServerErrors({ ...serverErrors, [k]: "" });
  };
  const err = (k: keyof BrandingSettings) => serverErrors[k] || undefined;

  const askReset = async () => {
    const ok = await confirm({
      title: "Reset branding to the defaults?",
      message: "This clears the organization name, product name, colors, theme choices, sign-in texts, support contact, report footer and every uploaded image. The previous values stay in the audit log.",
      confirmLabel: "Reset to defaults",
      danger: true,
    });
    if (ok) reset.mutate();
  };

  return (
    <div className="lp-branding">
      <div className="lp-stack-y">
        <Text c="dimmed" size="sm">
          Make this deployment look like yours. Everything here is stored on your server and changes are written to the audit log.
        </Text>

        <Card title="Names">
          <Stack gap="sm">
            <TextInput label="Organization name" description="Shown in the top bar, on the sign-in page, in page titles and on reports." value={draft.org_name} onChange={set("org_name")} maxLength={120} error={err("org_name")} />
            <TextInput
              label="Product name"
              description={`What the console calls itself. Leave empty for "${view.defaults.product_name}".`}
              placeholder={view.defaults.product_name}
              value={draft.product_name}
              onChange={set("product_name")}
              maxLength={60}
              error={err("product_name")}
            />
          </Stack>
        </Card>

        <Card title="Colors" description="The accent is adapted to every theme so text on it stays readable.">
          <Stack gap="sm">
            <ColorInput
              label="Accent color"
              description={`Buttons, links and focus rings. Leave empty for ${DEFAULT_ACCENT}.`}
              format="hex"
              placeholder={DEFAULT_ACCENT}
              value={draft.accent_color}
              onChange={(v) => setDraft({ ...draft, accent_color: v })}
              error={problems.accent ?? err("accent_color")}
              popoverProps={{ withinPortal: true }}
              withPicker={false}
              eyeDropperButtonProps={{ "aria-label": "Pick a color from the screen" }}
              swatches={ACCENT_SWATCHES}
              swatchesPerRow={6}
            />
            <ColorInput
              label="Secondary color (optional)"
              description="Used for graphics such as the line under the top bar."
              format="hex"
              placeholder="None"
              value={draft.secondary_color}
              onChange={(v) => setDraft({ ...draft, secondary_color: v })}
              error={problems.secondary ?? err("secondary_color")}
              popoverProps={{ withinPortal: true }}
              withPicker={false}
              eyeDropperButtonProps={{ "aria-label": "Pick a color from the screen" }}
              swatches={SECONDARY_SWATCHES}
              swatchesPerRow={6}
            />
            <ContrastTable rows={liveChecks} />
          </Stack>
        </Card>

        <Card title="Themes" description="Which themes people can use, and the one they start with, are set under Appearance.">
          <Link to="/settings/appearance">Open Appearance settings</Link>
        </Card>

        <Card title="Sign-in page">
          <Stack gap="sm">
            <TextInput label="Headline" placeholder={`Sign in to ${(draft.product_name ?? "").trim() || view.defaults.product_name}`} value={draft.login_headline} onChange={set("login_headline")} maxLength={120} error={err("login_headline")} />
            <Textarea label="Welcome message" autosize minRows={2} maxRows={6} value={draft.login_message} onChange={set("login_message")} maxLength={1000} error={err("login_message")} />
            <Textarea label="Footer or legal text (optional)" description="For example an authorized-use notice." autosize minRows={2} maxRows={6} value={draft.login_footer} onChange={set("login_footer")} maxLength={1000} error={err("login_footer")} />
            <Group grow align="flex-start">
              <TextInput label="Support email" type="email" value={draft.support_email} onChange={set("support_email")} error={err("support_email")} />
              <TextInput label="Support phone" value={draft.support_phone} onChange={set("support_phone")} error={err("support_phone")} />
            </Group>
            <TextInput label="Support link" description="An https:// address." placeholder="https://" value={draft.support_url} onChange={set("support_url")} error={err("support_url")} />
          </Stack>
        </Card>

        <Card title="Reports and emails">
          <Textarea label="Footer text" description="Printed at the bottom of exported reports and added to emails." autosize minRows={2} maxRows={6} value={draft.report_footer} onChange={set("report_footer")} maxLength={500} error={err("report_footer")} />
        </Card>

        <div className="lp-actionbar" role="group" aria-label="Save branding">
          <Button onClick={() => save.mutate()} loading={save.isPending} disabled={!dirty || blocked} leftSection={<Icons.Save size={16} aria-hidden />}>
            Save changes
          </Button>
          <Button variant="default" onClick={() => (setDraft(norm(view.settings)), setServerErrors({}))} disabled={!dirty}>
            Discard changes
          </Button>
          {dirty && (
            <StatusPill kind="warning" size="sm" icon={Icons.Clock}>
              Unsaved changes
            </StatusPill>
          )}
          <span className="lp-actionbar__spacer" />
          <Button variant="outline" color="red" onClick={() => void askReset()} loading={reset.isPending} leftSection={<Icons.Restore size={16} aria-hidden />}>
            Reset to defaults
          </Button>
          {blocked && (
            <Text size="sm" role="alert" style={{ flexBasis: "100%", color: "var(--lp-danger-fg)", display: "flex", alignItems: "center", gap: 6 }}>
              <Icons.Danger size={16} aria-hidden />
              {problems.accent || problems.secondary ? "These colors cannot be saved until they pass the contrast checks." : "Fix the highlighted fields to save."}
            </Text>
          )}
        </div>

        <Card title="Images" description="PNG or JPEG, up to 512 KB. Images are applied as soon as you upload them. They are re-encoded on the server, so metadata is removed. SVG is not accepted.">
          <div>
            {SLOTS.map((s) => (
              <ImageSlot key={s.kind} slot={s} view={view} onView={accept} />
            ))}
          </div>
        </Card>
      </div>

      <div className="lp-branding__preview">
        <Card title="Preview">
          <BrandPreview draft={draft} view={view} />
        </Card>
      </div>
    </div>
  );
}

function ContrastTable({ rows }: { rows: ReturnType<typeof checks> }) {
  if (rows.length === 0) return null;
  return (
    <div className="lp-minitable-wrap">
      <table className="lp-minitable" data-testid="contrast-table" aria-label="Contrast checks">
        <thead>
          <tr>
            <th scope="col">Where it is used (WCAG AA)</th>
            <th scope="col">Contrast</th>
            <th scope="col">Needs</th>
            <th scope="col">Result</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c) => (
            <tr key={c.id} data-testid={`contrast-${c.id}`}>
              <td>
                <span className="lp-swatch-dot" style={{ background: c.id.startsWith("accent_text") ? c.background : c.foreground }} aria-hidden="true" />
                {c.label}
              </td>
              <td className="lp-num">{c.ratio.toFixed(2)}:1</td>
              <td className="lp-num">{c.required.toFixed(1)}:1</td>
              <td>
                <StatusPill kind={c.pass ? "success" : "danger"} size="sm">
                  {c.pass ? "Pass" : "Fail"}
                </StatusPill>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ImageSlot({ slot, view, onView }: { slot: (typeof SLOTS)[number]; view: BrandingView; onView: (v: BrandingView) => void }) {
  const info = view.assets[slot.kind];
  const confirm = useConfirm();
  const [err, setErr] = useState("");
  const clearInput = useRef<() => void>(null);
  const upload = useMutation({
    mutationFn: async (file: File) => {
      await checkImageFile(file, slot.kind);
      return uploadBrandingAsset(slot.kind, file);
    },
    onSuccess: (v) => (setErr(""), onView(v), toast.success(`${slot.label} updated.`)),
    onError: (e) => setErr(errorMessage(e)),
  });
  const remove = useMutation({
    mutationFn: () => api<BrandingView>("DELETE", `/settings/branding/assets/${slot.kind}`),
    onSuccess: (v) => (setErr(""), onView(v), toast.success(`${slot.label} removed.`)),
    onError: (e) => setErr(errorMessage(e)),
  });
  // A logo made for light or dark backgrounds is previewed on a fixed light or dark surface in every theme.
  const background = slot.surface === "dark" ? DARK_SURFACE : slot.surface === "light" ? WHITE : undefined;
  return (
    <div className="lp-slot" data-testid={`slot-${slot.kind}`}>
      <div className="lp-slot__preview" style={background ? { background } : undefined}>
        {info ? <img src={info.url} alt={`${slot.label} (current)`} style={{ maxWidth: 112, maxHeight: 56 }} /> : <span style={background ? { color: slot.surface === "dark" ? WHITE : DARK_SURFACE } : undefined}>None</span>}
      </div>
      <div className="lp-slot__body">
        <p className="lp-slot__title">{slot.label}</p>
        <p className="lp-slot__help">
          {slot.help} {LIMITS[slot.kind].hint}.{info ? ` Current: ${info.width} × ${info.height}, ${(info.size / 1024).toFixed(1)} KB.` : ""}
        </p>
        <Group gap="xs">
          <FileButton
            accept="image/png,image/jpeg"
            resetRef={clearInput}
            onChange={(f) => {
              clearInput.current?.(); // choosing the same file again must work after a failure or a removal
              if (f) upload.mutate(f);
            }}
          >
            {(props) => (
              <Button {...props} size="xs" variant="default" loading={upload.isPending} aria-label={`${info ? "Replace" : "Upload"} ${slot.label}`} leftSection={<Icons.Plus size={14} aria-hidden />}>
                {info ? "Replace" : "Upload"}
              </Button>
            )}
          </FileButton>
          {info && (
            <Button
              size="xs"
              variant="subtle"
              color="red"
              loading={remove.isPending}
              aria-label={`Remove ${slot.label}`}
              leftSection={<Icons.Trash size={14} aria-hidden />}
              onClick={async () => {
                const ok = await confirm({ title: `Remove “${slot.label}”?`, message: "The image is deleted from the server. You can upload it again at any time.", confirmLabel: "Remove image", danger: true });
                if (ok) remove.mutate();
              }}
            >
              Remove
            </Button>
          )}
        </Group>
        {err && (
          <p className="lp-slot__error" role="alert">
            <Icons.Danger size={14} aria-hidden />
            {err}
          </p>
        )}
      </div>
    </div>
  );
}
