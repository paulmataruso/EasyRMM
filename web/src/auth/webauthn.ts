// Security keys and passkeys in the browser (ADR-0032). The server sends WebAuthn options as JSON, with binary
// values in unpadded base64url; the browser API wants ArrayBuffers. These helpers convert both ways, call
// navigator.credentials, and turn the browser's errors into sentences a technician can act on.

import type { WebAuthnStatus } from "../api/types";

type Json = Record<string, unknown>;

export function fromBase64url(value: string): ArrayBuffer {
  const b64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

export function toBase64url(value: ArrayBuffer | ArrayBufferView): string {
  const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Whether this browser has the WebAuthn API at all. */
export function browserSupportsKeys(): boolean {
  return typeof window.PublicKeyCredential === "function" && typeof navigator.credentials?.get === "function";
}

export type KeyAvailability = { usable: true } | { usable: false; why: "server" | "browser" | "address"; message: string; origin?: string };

/**
 * Whether security keys and passkeys can be used on this page. The server must have a name (not an IP address),
 * the browser must support them, and the page must be at the server's public address: the browser binds each
 * key to that name.
 */
export function keyAvailability(status: WebAuthnStatus | undefined): KeyAvailability {
  if (!status?.available) return { usable: false, why: "server", message: status?.reason || "Security keys and passkeys are not available on this server." };
  if (!browserSupportsKeys()) return { usable: false, why: "browser", message: "This browser cannot use security keys or passkeys." };
  if (status.origin && window.location.origin !== status.origin) {
    return { usable: false, why: "address", origin: status.origin, message: `Security keys and passkeys work only at ${status.origin}.` };
  }
  return { usable: true };
}

function publicKey(options: unknown): Json {
  const pk = (options as { publicKey?: Json } | null)?.publicKey;
  if (!pk || typeof pk.challenge !== "string") throw new Error("The server's request for a security key is incomplete.");
  return pk;
}

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return list.map((d: Json) => ({ ...d, type: "public-key", id: fromBase64url(String(d.id)) }) as PublicKeyCredentialDescriptor);
}

/** Converts the server's registration options into what navigator.credentials.create() takes. */
export function creationOptions(options: unknown): CredentialCreationOptions {
  const pk = publicKey(options);
  const user = pk.user as Json;
  return {
    publicKey: {
      ...(pk as unknown as PublicKeyCredentialCreationOptions),
      challenge: fromBase64url(pk.challenge as string),
      user: { ...(user as unknown as PublicKeyCredentialUserEntity), id: fromBase64url(String(user.id)) },
      excludeCredentials: descriptors(pk.excludeCredentials),
    },
  };
}

/** Converts the server's sign-in options into what navigator.credentials.get() takes. */
export function requestOptions(options: unknown): CredentialRequestOptions {
  const pk = publicKey(options);
  return {
    publicKey: {
      ...(pk as unknown as PublicKeyCredentialRequestOptions),
      challenge: fromBase64url(pk.challenge as string),
      allowCredentials: descriptors(pk.allowCredentials),
    },
  };
}

/** The credential as JSON, in the form of PublicKeyCredential.toJSON(), which not every browser has yet. */
export function credentialJSON(cred: PublicKeyCredential): Json {
  const r = cred.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
  const response: Json = { clientDataJSON: toBase64url(r.clientDataJSON) };
  if ("attestationObject" in r && r.attestationObject) {
    response.attestationObject = toBase64url(r.attestationObject);
    response.transports = typeof r.getTransports === "function" ? r.getTransports() : [];
  } else {
    response.authenticatorData = toBase64url(r.authenticatorData);
    response.signature = toBase64url(r.signature);
    if (r.userHandle) response.userHandle = toBase64url(r.userHandle);
  }
  return {
    id: cred.id,
    rawId: toBase64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
    response,
  };
}

/**
 * What sign-in says when the browser's prompt ends without a key. Browsers report a closed prompt and a prompt
 * that found no matching key the same way, so this covers both. Behind the second is often a password manager
 * that did not answer (locked, or updated since the page loaded), which reloading the page fixes.
 */
export const NO_KEY_ANSWERED = "No passkey or security key answered. If yours wasn't offered, reload the page and try again.";

/** Thrown when the browser's prompt ended without a key: closed, timed out, or no key matched. Not an error. */
export class KeyCancelled extends Error {
  constructor() {
    super("Cancelled.");
    this.name = "KeyCancelled";
  }
}

function explain(err: unknown, creating: boolean): Error {
  const name = err instanceof DOMException || err instanceof Error ? err.name : "";
  switch (name) {
    case "NotAllowedError":
    case "AbortError":
      // Also what browsers report when the prompt times out, or no key matched; they do not say which.
      return new KeyCancelled();
    case "InvalidStateError":
      return new Error(creating ? "This security key is already registered to your account. Use a different key." : "That security key could not be used.");
    case "SecurityError":
      return new Error("The browser refused, because this page's address does not match EasyRMM's public address.");
    case "NotSupportedError":
      return new Error("This security key cannot do what EasyRMM asked for. Try a different key or passkey.");
  }
  return new Error("The security key or passkey did not respond. Try again.");
}

/** Asks the browser to create a credential for the server's options; returns it as JSON for the server. */
export async function createKey(options: unknown): Promise<Json> {
  let cred: Credential | null;
  try {
    cred = await navigator.credentials.create(creationOptions(options));
  } catch (err) {
    throw explain(err, true);
  }
  if (!cred) throw new KeyCancelled();
  return credentialJSON(cred as PublicKeyCredential);
}

/** Asks the browser for a credential matching the server's options; returns it as JSON for the server. */
export async function getKey(options: unknown): Promise<Json> {
  let cred: Credential | null;
  try {
    cred = await navigator.credentials.get(requestOptions(options));
  } catch (err) {
    throw explain(err, false);
  }
  if (!cred) throw new KeyCancelled();
  return credentialJSON(cred as PublicKeyCredential);
}
