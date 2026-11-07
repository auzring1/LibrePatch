import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Checkbox } from "@mantine/core";
import { useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Alert, Anchor, Button, PasswordInput, Stack, Text, TextInput } from "@mantine/core";
import { api, errorMessage, setCsrf } from "../api/client";
import { useSession } from "../api/session";
import { CodeInput, RecoveryCodes, TotpQR } from "../components/common";
import { getAssertion, webauthnSupported } from "../api/webauthn";
import { useBranding, useDocumentTitle } from "../branding/BrandingProvider";
import { Icons } from "../ui";
import { AuthBrand, AuthShell } from "../ui/admin-kit";

type Stage =
  | { kind: "password" }
  | { kind: "change_password" }
  | { kind: "verify"; methods: string[] }
  | { kind: "enroll"; secret: string; uri: string }
  | { kind: "codes"; codes: string[] };

export function LoginPage() {
  const nav = useNavigate();
  const { refresh } = useSession();
  const brand = useBranding();
  useDocumentTitle("Sign in");
  const [stage, setStage] = useState<Stage>({ kind: "password" });
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newPassword2, setNewPassword2] = useState("");
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const notice = useQuery({ queryKey: ["auth-notice"], queryFn: () => api<{ enabled: boolean; text: string; require_ack: boolean }>("GET", "/auth/notice"), staleTime: 60_000, retry: false });
  const [accepted, setAccepted] = useState(false);
  const sso = useQuery({ queryKey: ["sso-info"], queryFn: () => api<{ enabled: boolean; label: string }>("GET", "/auth/sso/info"), staleTime: 60_000, retry: false });
  const [params, setParams] = useSearchParams();
  const noticeOn = !!notice.data?.enabled;
  const mustAccept = noticeOn && !!notice.data?.require_ack && !accepted;

  const run = async (fn: () => Promise<void>) => {
    setErr("");
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  type Next = { mfa: string; csrf_token: string; totp_secret?: string; otpauth_uri?: string; methods?: string[] };
  const proceed = (r: Next) => {
    setCsrf(r.csrf_token);
    if (r.mfa === "change_password") setStage({ kind: "change_password" });
    else if (r.mfa === "enroll") setStage({ kind: "enroll", secret: r.totp_secret ?? "", uri: r.otpauth_uri ?? "" });
    else setStage({ kind: "verify", methods: r.methods ?? ["totp"] });
  };

  // Back from the identity provider: either a message about why not, or the second-factor step of a sign-in that has begun.
  const ssoError = params.get("sso_error");
  const ssoContinue = params.get("sso") === "continue";
  useEffect(() => {
    if (!ssoContinue) return;
    setParams({}, { replace: true });
    void run(async () => proceed(await api<Next>("GET", "/auth/sso/continue")));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ssoContinue]);

  const login = () =>
    run(async () => {
      proceed(await api<Next>("POST", "/auth/login", { email: email.trim(), password }));
    });

  const changePassword = () =>
    run(async () => {
      if (newPassword !== newPassword2) throw new Error("The two new passwords are not the same.");
      proceed(await api<Next>("POST", "/auth/change-password", { current_password: password, new_password: newPassword }));
      setPassword("");
      setNewPassword("");
      setNewPassword2("");
    });

  const useKey = () =>
    run(async () => {
      const begin = await api<{ ceremony: string; options: { publicKey: Record<string, unknown> } }>("POST", "/auth/webauthn/begin", {});
      const cred = await getAssertion(begin.options);
      await finish(await api("POST", `/auth/webauthn/finish?ceremony=${begin.ceremony}`, cred));
    });

  const finish = async (r: { csrf_token: string; recovery_codes?: string[] }) => {
    setCsrf(r.csrf_token);
    if (r.recovery_codes?.length) {
      setStage({ kind: "codes", codes: r.recovery_codes });
      return;
    }
    await refresh();
    nav("/", { replace: true });
  };

  const verify = () =>
    run(async () => {
      try {
        await finish(await api("POST", "/auth/mfa", { code: code.trim() }));
      } catch (e) {
        setCode("");
        if ((e as { code?: string }).code === "mfa_locked") setStage({ kind: "password" });
        throw e;
      }
    });

  const enroll = () => run(async () => finish(await api("POST", "/auth/mfa/enroll", { code })));

  return (
    <AuthShell below={<LoginFooter />}>
      <Stack gap="xs">
        <AuthBrand />
        <h1 className="lp-auth__title" data-testid="login-headline">
          {brand.login_headline || `Sign in to ${brand.product_name}`}
        </h1>
        {brand.org_name && (
          <p className="lp-auth__org" data-testid="login-org">
            {brand.org_name}
          </p>
        )}
        {brand.login_message && (
          <p className="lp-auth__msg" data-testid="login-message">
            {brand.login_message}
          </p>
        )}
      </Stack>
      {stage.kind === "password" && noticeOn && (
        <section className="lp-auth__notice" aria-label="Notice" data-testid="login-notice">
          <p style={{ margin: 0, whiteSpace: "pre-wrap" }}>{notice.data!.text}</p>
          {notice.data!.require_ack && <Checkbox mt="xs" label="I have read and accept this notice" checked={accepted} onChange={(e) => setAccepted(e.currentTarget.checked)} />}
        </section>
      )}
      {stage.kind === "password" && (
        <form onSubmit={(e) => (e.preventDefault(), mustAccept ? undefined : void login())}>
          <Stack>
            <TextInput label="Email" type="email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} autoComplete="username" required autoFocus />
            <PasswordInput label="Password" value={password} onChange={(e) => setPassword(e.currentTarget.value)} autoComplete="current-password" required />
            <Button type="submit" loading={busy} disabled={mustAccept} fullWidth>
              Continue
            </Button>
            {sso.data?.enabled && (
              <>
                <Text size="sm" c="dimmed" ta="center">
                  or
                </Text>
                <Button component="a" href={mustAccept ? undefined : "/api/v1/auth/sso/start"} variant="default" disabled={mustAccept} fullWidth leftSection={<Icons.NavSecurity size={16} aria-hidden />} data-testid="sso-button">
                  Sign in with {sso.data.label}
                </Button>
              </>
            )}
          </Stack>
        </form>
      )}
      {stage.kind === "password" && ssoError && (
        <Alert color="red" role="alert" icon={<Icons.Danger size={18} aria-hidden />} data-testid="sso-error">
          {ssoMessage(ssoError)}
        </Alert>
      )}
      {stage.kind === "change_password" && (
        <form onSubmit={(e) => (e.preventDefault(), void changePassword())}>
          <Stack>
            <Alert color="blue" icon={<Icons.Info size={18} aria-hidden />}>
              An administrator set a temporary password for you. Choose your own to continue.
            </Alert>
            <PasswordInput label="New password" value={newPassword} onChange={(e) => setNewPassword(e.currentTarget.value)} autoComplete="new-password" required autoFocus />
            <PasswordInput label="Repeat the new password" value={newPassword2} onChange={(e) => setNewPassword2(e.currentTarget.value)} autoComplete="new-password" required />
            <Button type="submit" loading={busy} fullWidth>
              Change password
            </Button>
          </Stack>
        </form>
      )}
      {stage.kind === "verify" && (
        <form onSubmit={(e) => (e.preventDefault(), void verify())}>
          <Stack>
            {stage.methods.includes("webauthn") && webauthnSupported() && (
              <Button variant="default" onClick={() => void useKey()} loading={busy} leftSection={<Icons.NavEnrollment size={16} aria-hidden />} fullWidth>
                Use a security key
              </Button>
            )}
            {useRecovery ? (
              <TextInput label="Recovery code" placeholder="xxxx-xxxx-xxxx" value={code} onChange={(e) => setCode(e.currentTarget.value)} autoComplete="off" autoFocus />
            ) : (
              <>
                <Text size="sm">Enter the 6-digit code from your authenticator app.</Text>
                <CodeInput autoFocus value={code} onChange={setCode} />
              </>
            )}
            <Button type="submit" loading={busy} disabled={!code} fullWidth style={{ display: stage.methods.includes("totp") || useRecovery ? undefined : "none" }}>
              Verify
            </Button>
            <Anchor component="button" type="button" size="sm" onClick={() => (setUseRecovery(!useRecovery), setCode(""))}>
              {useRecovery ? "Use authenticator code" : "Use a recovery code instead"}
            </Anchor>
          </Stack>
        </form>
      )}
      {stage.kind === "enroll" && (
        <Stack>
          <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />}>
            Your multi-factor authentication was reset. Set up an authenticator to continue.
          </Alert>
          <TotpQR uri={stage.uri} secret={stage.secret} />
          <CodeInput value={code} onChange={setCode} />
          <Button onClick={enroll} loading={busy} disabled={code.length !== 6} fullWidth>
            Confirm
          </Button>
        </Stack>
      )}
      {stage.kind === "codes" && (
        <Stack>
          <RecoveryCodes codes={stage.codes} />
          <Button onClick={() => void refresh().then(() => nav("/", { replace: true }))} fullWidth>
            I have saved them, continue
          </Button>
        </Stack>
      )}
      {err && (
        <Alert color="red" role="alert" icon={<Icons.Danger size={18} aria-hidden />}>
          {err}
        </Alert>
      )}
    </AuthShell>
  );
}

/** The optional legal text and support contact under the sign-in card. Everything here is plain text or a checked link. */
function LoginFooter() {
  const { login_footer: footer, support } = useBranding();
  if (!footer && !support.email && !support.phone && !support.url) return null;
  return (
    <Stack gap={4} align="center" data-testid="login-footer">
      {footer && <p className="lp-auth__foot">{footer}</p>}
      {(support.email || support.phone || support.url) && (
        <p className="lp-auth__help">
          Need help?{" "}
          {support.email && <a href={`mailto:${support.email}`}>{support.email}</a>}
          {support.email && (support.phone || support.url) && " · "}
          {support.phone && <a href={`tel:${support.phone.replace(/[^0-9+]/g, "")}`}>{support.phone}</a>}
          {support.phone && support.url && " · "}
          {support.url && (
            <a href={support.url} target="_blank" rel="noopener noreferrer">
              Support site
            </a>
          )}
        </p>
      )}
    </Stack>
  );
}

/** What the person sees when single sign-on did not work. The reason in detail is in the audit log, not here. */
export function ssoMessage(code: string): string {
  switch (code) {
    case "no_access":
      return "Your company account is not allowed to use this system. Ask an administrator to give you a role.";
    case "account_exists":
      return "An account with your email address already exists here but is not linked to your company account. Ask an administrator.";
    case "disabled":
      return "Your account here has been switched off. Ask an administrator.";
    case "expired":
      return "That sign-in took too long or was already used. Try again.";
    case "denied":
      return "Your company sign-in was cancelled or refused.";
    case "rate_limited":
      return "Too many sign-in attempts. Wait a minute and try again.";
    case "unavailable":
      return "Single sign-on is not available right now. Use your password, or try again later.";
    default:
      return "Single sign-on did not work. Try again, or use your password.";
  }
}
