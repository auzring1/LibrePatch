import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Checkbox, FileInput, PasswordInput, Stack, Stepper, Text, TextInput } from "@mantine/core";
import { api, errorMessage } from "../api/client";
import { CodeInput, RecoveryCodes, TotpQR } from "../components/common";
import { useBranding, useDocumentTitle } from "../branding/BrandingProvider";
import { base64Of, checkImageFile, type LocalImage } from "../branding/images";
import { Icons } from "../ui";
import { AuthBrand, AuthShell } from "../ui/admin-kit";

export function SetupPage() {
  const nav = useNavigate();
  const qc = useQueryClient();
  const { product_name: productName } = useBranding();
  useDocumentTitle("Set up");
  const [logo, setLogo] = useState<LocalImage | null>(null);
  const [logoErr, setLogoErr] = useState("");
  const [step, setStep] = useState(0);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [f, setF] = useState({ token: "", email: "", org: "", name: "", password: "", password2: "", root: "", root2: "", code: "" });
  const [totp, setTotp] = useState<{ totp_secret: string; otpauth_uri: string } | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [saved, setSaved] = useState(false);
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.currentTarget.value });

  const begin = async () => {
    setErr("");
    setBusy(true);
    try {
      setTotp(await api("POST", "/setup/begin", { setup_token: f.token.trim(), email: f.email.trim() }));
      setStep(1);
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const complete = async () => {
    setErr("");
    if (f.password !== f.password2) return setErr("The passwords do not match.");
    if (f.root !== f.root2) return setErr("The CA passphrases do not match.");
    setBusy(true);
    try {
      const r = await api<{ recovery_codes: string[] }>("POST", "/setup/complete", {
        setup_token: f.token.trim(),
        org_name: f.org,
        display_name: f.name,
        email: f.email.trim(),
        password: f.password,
        root_passphrase: f.root,
        totp_code: f.code,
        ...(logo ? { logo_base64: base64Of(logo.dataUrl) } : {}),
      });
      setCodes(r.recovery_codes);
      setStep(2);
      await qc.invalidateQueries({ queryKey: ["setup"] });
      await qc.invalidateQueries({ queryKey: ["branding"] }); // the organization name and logo now exist
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell width={640}>
      <Stack gap="xs">
        <AuthBrand />
        <h1 className="lp-auth__title">Set up {productName}</h1>
        <p className="lp-auth__org">Create the first administrator and the organization. This page is only available until setup is complete.</p>
      </Stack>
      <Stepper active={step} size="sm" allowNextStepsSelect={false}>
        <Stepper.Step label="Verify" description="Setup token">
          <Stack mt="md">
            <Text size="sm">
              Enter the one-time setup token printed in the server log (<code>docker compose logs server</code>) and the email address of the first administrator.
            </Text>
            <TextInput label="Setup token" value={f.token} onChange={set("token")} autoComplete="off" required />
            <TextInput label="Administrator email" type="email" value={f.email} onChange={set("email")} autoComplete="username" required />
            <Button onClick={begin} loading={busy} disabled={!f.token || !f.email}>
              Continue
            </Button>
          </Stack>
        </Stepper.Step>
        <Stepper.Step label="Administrator" description="Account, MFA and CA">
          <Stack mt="md">
            <TextInput
              label="Organization name"
              description="Shown in the top bar, on the sign-in page and on reports. You can change it later under Settings > Branding."
              value={f.org}
              onChange={set("org")}
              maxLength={120}
              required
            />
            <FileInput
              label="Logo (optional)"
              description="PNG or JPEG, up to 512 KB. You can add more images later under Settings > Branding."
              placeholder="Choose a logo"
              accept="image/png,image/jpeg"
              clearable
              clearButtonProps={{ "aria-label": "Remove the chosen logo" }}
              onChange={(file) => {
                setLogoErr("");
                if (!file) return setLogo(null);
                checkImageFile(file, "logo_light").then(setLogo, (e: Error) => (setLogo(null), setLogoErr(e.message)));
              }}
              error={logoErr || undefined}
            />
            {logo && (
              <img
                src={logo.dataUrl}
                alt="Logo preview"
                data-testid="setup-logo-preview"
                style={{ maxHeight: 64, maxWidth: 240, objectFit: "contain", alignSelf: "flex-start", padding: 8, border: "1px solid var(--lp-border)", borderRadius: "var(--lp-radius-md)", background: "var(--lp-surface-sunken)" }}
              />
            )}
            <TextInput label="Your name" value={f.name} onChange={set("name")} autoComplete="name" required />
            <PasswordInput
              label="Password"
              description="At least 12 characters. Long passphrases are best; common or breached passwords are rejected."
              value={f.password}
              onChange={set("password")}
              autoComplete="new-password"
              required
            />
            <PasswordInput label="Confirm password" value={f.password2} onChange={set("password2")} autoComplete="new-password" required />
            <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />} title="Certificate authority passphrase">
              This passphrase protects the root of trust for every agent. It is never stored by the server. You will need it for rare CA operations (rotating signing keys). Keep it offline, separate from your password.
            </Alert>
            <PasswordInput label="CA root passphrase (16+ characters)" value={f.root} onChange={set("root")} autoComplete="off" required />
            <PasswordInput label="Confirm CA root passphrase" value={f.root2} onChange={set("root2")} autoComplete="off" required />
            {totp && (
              <>
                <Text fw={600}>Multi-factor authentication (required)</Text>
                <Text size="sm">Scan this code with an authenticator app (Microsoft Authenticator, 1Password, Google Authenticator…).</Text>
                <TotpQR uri={totp.otpauth_uri} secret={totp.totp_secret} />
              </>
            )}
            <CodeInput value={f.code} onChange={(v) => setF({ ...f, code: v })} />
            <Button onClick={complete} loading={busy} disabled={f.code.length !== 6}>
              Create organization
            </Button>
          </Stack>
        </Stepper.Step>
        <Stepper.Step label="Recovery codes">
          <Stack mt="md">
            <RecoveryCodes codes={codes} />
            <Checkbox label="I have saved my recovery codes" checked={saved} onChange={(e) => setSaved(e.currentTarget.checked)} />
            <Button disabled={!saved} onClick={() => nav("/login", { replace: true })}>
              Continue to sign in
            </Button>
          </Stack>
        </Stepper.Step>
      </Stepper>
      {err && (
        <Alert color="red" role="alert" icon={<Icons.Danger size={18} aria-hidden />}>
          {err}
        </Alert>
      )}
    </AuthShell>
  );
}
