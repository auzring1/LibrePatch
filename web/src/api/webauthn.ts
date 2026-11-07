// WebAuthn helpers: the server sends/accepts the JSON forms the go-webauthn library uses, with
// base64url-encoded binary fields. These convert them for navigator.credentials.

const b64uToBuf = (s: string): ArrayBuffer => {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
};

const bufToB64u = (b: ArrayBuffer | null): string => {
  if (!b) return "";
  let s = "";
  for (const x of new Uint8Array(b)) s += String.fromCharCode(x);
  const b64 = btoa(s).replace(/\+/g, "-").replace(/\//g, "_");
  let end = b64.length; // padding off, by hand (a trailing-run regex backtracks)
  while (end > 0 && b64[end - 1] === "=") end--;
  return b64.slice(0, end);
};

export const webauthnSupported = () => typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;

interface Desc {
  id: string;
  type: PublicKeyCredentialType;
  transports?: AuthenticatorTransport[];
}

/** Runs navigator.credentials.create with server options and returns the body for /finish. */
export async function createCredential(options: { publicKey: Record<string, unknown> }): Promise<unknown> {
  const pk = options.publicKey as {
    challenge: string;
    user: { id: string; name: string; displayName: string };
    excludeCredentials?: Desc[];
  } & Record<string, unknown>;
  const cred = (await navigator.credentials.create({
    publicKey: {
      ...pk,
      challenge: b64uToBuf(pk.challenge),
      user: { ...pk.user, id: b64uToBuf(pk.user.id) },
      excludeCredentials: (pk.excludeCredentials ?? []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
    } as unknown as PublicKeyCredentialCreationOptions,
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No security key was selected.");
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: { attestationObject: bufToB64u(r.attestationObject), clientDataJSON: bufToB64u(r.clientDataJSON), transports: r.getTransports?.() ?? [] },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

/** Runs navigator.credentials.get with server options and returns the body for /finish. */
export async function getAssertion(options: { publicKey: Record<string, unknown> }): Promise<unknown> {
  const pk = options.publicKey as { challenge: string; allowCredentials?: Desc[] } & Record<string, unknown>;
  const cred = (await navigator.credentials.get({
    publicKey: {
      ...pk,
      challenge: b64uToBuf(pk.challenge),
      allowCredentials: (pk.allowCredentials ?? []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
    } as unknown as PublicKeyCredentialRequestOptions,
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No security key was selected.");
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: bufToB64u(r.authenticatorData),
      clientDataJSON: bufToB64u(r.clientDataJSON),
      signature: bufToB64u(r.signature),
      userHandle: bufToB64u(r.userHandle),
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}
