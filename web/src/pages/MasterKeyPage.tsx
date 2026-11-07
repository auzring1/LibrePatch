import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Alert, Button, Checkbox, CopyButton, Group, Stack, Text, TextInput } from "@mantine/core";
import { api, ApiError, errorMessage } from "../api/client";
import { useSession } from "../api/session";
import { useBranding, useDocumentTitle } from "../branding/BrandingProvider";
import { Icons, toast } from "../ui";
import { AuthBrand, AuthShell } from "../ui/admin-kit";
import { CopyText } from "../components/common";
import { masterKeyFile, type MasterKey } from "./masterKeyFile";

/**
 * Shown to the first administrator when the stack generated its own master key, and nothing else works until they have
 * saved it (decision D109). Confirming needs the last six characters of the key, so a click is not enough.
 */
export function MasterKeyPage() {
  const { session, refresh } = useSession();
  const { product_name: productName } = useBranding();
  useDocumentTitle("Save your master key");
  const [saved, setSaved] = useState(false);
  const [tail, setTail] = useState("");
  const q = useQuery({ queryKey: ["master-key"], queryFn: () => api<MasterKey>("GET", "/security/master-key"), retry: false, staleTime: Infinity, gcTime: 0 });
  const confirm = useMutation({
    mutationFn: () => api("POST", "/security/master-key/acknowledge", { confirm: tail.trim() }),
    onSuccess: async () => {
      toast.success("Thank you. The master key is saved.");
      await refresh();
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const signOut = async () => {
    await api("POST", "/auth/logout", {}).catch(() => undefined);
    await refresh();
  };
  const notAllowed = q.error instanceof ApiError && q.error.status === 403;
  const download = () => {
    if (!q.data) return;
    const blob = new Blob([masterKeyFile(productName, q.data)], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${productName.toLowerCase()}-master-key.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  return (
    <AuthShell width={640}>
      <Stack gap="xs">
        <AuthBrand />
        <h1 className="lp-auth__title">Save your master key</h1>
        <p className="lp-auth__org">{session?.org.name}</p>
      </Stack>
      {notAllowed ? (
        <Stack>
          <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />}>
            An administrator has to save the master key before anyone can use {productName}. Ask the person who set it up, then sign in again.
          </Alert>
          <Button variant="default" onClick={signOut}>
            Sign out
          </Button>
        </Stack>
      ) : (
        <Stack>
          <Text size="sm">
            This server created a <b>master key</b> to encrypt its most sensitive data: the certificate authority keys and everyone's authenticator secrets. It is shown
            <b> only here, only now</b>. Without it, a restored backup or a rebuilt server cannot be read.
          </Text>
          <Alert color="orange" icon={<Icons.Warning size={18} aria-hidden />} title="Keep it away from this server">
            Save it in a password manager or print it and put it in a safe. Do not keep the only copy on the server or in its backups.
          </Alert>
          {q.isLoading && <Text size="sm">Loading the key…</Text>}
          {q.error && !notAllowed && <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>{errorMessage(q.error)}</Alert>}
          {q.data && (
            <>
              <CopyText value={q.data.key} label="Copy the master key" />
              <Text size="xs" c="dimmed">
                Key id {q.data.key_id}: a short fingerprint, safe to write down, to recognise the right key later.
              </Text>
              <Group>
                <CopyButton value={q.data.key}>
                  {({ copied, copy }) => (
                    <Button variant="light" onClick={copy} leftSection={copied ? <Icons.Check size={16} aria-hidden /> : <Icons.Copy size={16} aria-hidden />}>
                      {copied ? "Copied" : "Copy key"}
                    </Button>
                  )}
                </CopyButton>
                <Button variant="light" onClick={download} leftSection={<Icons.Download size={16} aria-hidden />}>
                  Download .txt
                </Button>
              </Group>
              <Checkbox label="I have saved the master key somewhere other than this server" checked={saved} onChange={(e) => setSaved(e.currentTarget.checked)} />
              <TextInput
                label="Type the last six characters of the key"
                description="This proves you have the key in front of you."
                value={tail}
                onChange={(e) => setTail(e.currentTarget.value)}
                autoComplete="off"
                spellCheck={false}
                maxLength={32}
                disabled={!saved}
                styles={{ input: { fontFamily: "var(--lp-font-mono)" } }}
              />
              <Group justify="space-between">
                <Button variant="subtle" onClick={signOut}>
                  Sign out
                </Button>
                <Button onClick={() => confirm.mutate()} loading={confirm.isPending} disabled={!saved || tail.trim().length < 6}>
                  Continue
                </Button>
              </Group>
            </>
          )}
        </Stack>
      )}
    </AuthShell>
  );
}
