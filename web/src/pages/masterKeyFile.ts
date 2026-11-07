export interface MasterKey {
  key: string;
  key_id: string;
  generated_at: string;
}

/** The text a person saves: the key, its short id, and what it is for. */
export function masterKeyFile(productName: string, k: MasterKey): string {
  return [
    `${productName} master key`,
    "",
    `Master key: ${k.key}`,
    `Key id:     ${k.key_id}`,
    `Created:    ${k.generated_at}`,
    "",
    "This key opens the encrypted data of one server: the certificate authority keys and everyone's authenticator secrets.",
    "Keep it somewhere that is NOT on the server itself (a password manager or a safe). Anyone who has it and a copy of the",
    "database can read that data. Without it, a restored backup or a rebuilt server cannot be read.",
    "",
    "To put it back on a new server, give this file to: docker compose run --rm --no-deps -T maintenance set-master-key",
    "",
  ].join("\n");
}
