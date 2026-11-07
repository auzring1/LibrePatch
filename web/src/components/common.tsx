import { useEffect, useState } from "react";
import { ActionIcon, Button, CopyButton, Group, Stack, Text, TextInput, Tooltip } from "@mantine/core";
import QRCode from "qrcode";
import { PRODUCT_NAME } from "../brand.generated";
import { Icons, Status } from "../ui";
import "../ui/admin-kit.css";

/** A status word from the API (active, pending, revoked...) as an icon + color + text pill. */
export function StatusBadge({ status }: { status: string }) {
  return <Status value={status} size="sm" />;
}

export function OnlineDot({ online }: { online: boolean }) {
  return <Status value={online ? "online" : "offline"} size="sm" />;
}

/** A value in a monospace block with a copy button. The block is a <pre> so line breaks survive. */
export function CopyText({ value, label }: { value: string; label?: string }) {
  return (
    <div className="lp-copytext">
      <pre>{value}</pre>
      <CopyButton value={value}>
        {({ copied, copy }) => (
          <Tooltip label={copied ? "Copied" : (label ?? "Copy")}>
            <ActionIcon variant="light" onClick={copy} aria-label={label ?? "Copy"}>
              {copied ? <Icons.Check size={16} aria-hidden /> : <Icons.Copy size={16} aria-hidden />}
            </ActionIcon>
          </Tooltip>
        )}
      </CopyButton>
    </div>
  );
}

/** Renders an otpauth:// URI as a QR code (data: image, allowed by the CSP). */
export function TotpQR({ uri, secret }: { uri: string; secret: string }) {
  const [src, setSrc] = useState("");
  useEffect(() => {
    void QRCode.toDataURL(uri, { margin: 1, width: 200 }).then(setSrc);
  }, [uri]);
  return (
    <Stack gap="xs" align="flex-start">
      {src && (
        <span className="lp-qr">
          <img src={src} width={200} height={200} alt="Authenticator QR code" />
        </span>
      )}
      <Text size="sm" c="dimmed">
        Can't scan? Enter this key in your authenticator app:
      </Text>
      <div style={{ width: "100%" }}>
        <CopyText value={secret} label="Copy key" />
      </div>
    </Stack>
  );
}

export function RecoveryCodes({ codes }: { codes: string[] }) {
  const download = () => {
    const blob = new Blob([`${PRODUCT_NAME} recovery codes (each works once)\n\n${codes.join("\n")}\n`], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${PRODUCT_NAME.toLowerCase()}-recovery-codes.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  return (
    <Stack gap="sm">
      <Text size="sm">
        Store these recovery codes somewhere safe, such as a password manager. Each one can be used once if you lose your
        authenticator. They will not be shown again.
      </Text>
      <ul className="lp-codes" aria-label="Recovery codes">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <Group>
        <CopyButton value={codes.join("\n")}>
          {({ copied, copy }) => (
            <Button variant="light" onClick={copy} leftSection={copied ? <Icons.Check size={16} aria-hidden /> : <Icons.Copy size={16} aria-hidden />}>
              {copied ? "Copied" : "Copy codes"}
            </Button>
          )}
        </CopyButton>
        <Button variant="light" onClick={download} leftSection={<Icons.Download size={16} aria-hidden />}>
          Download .txt
        </Button>
      </Group>
    </Stack>
  );
}

/** One field for a 6-digit authenticator code (paste- and autofill-friendly). */
export function CodeInput({ value, onChange, autoFocus }: { value: string; onChange: (v: string) => void; autoFocus?: boolean }) {
  return (
    <TextInput
      label="Authenticator code"
      placeholder="123456"
      inputMode="numeric"
      autoComplete="one-time-code"
      maxLength={6}
      autoFocus={autoFocus}
      value={value}
      onChange={(e) => onChange(e.currentTarget.value.replace(/\D/g, "").slice(0, 6))}
      styles={{ input: { letterSpacing: "0.3em", fontFamily: "var(--lp-font-mono)" } }}
      w={180}
    />
  );
}
