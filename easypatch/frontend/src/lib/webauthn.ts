// Security keys and passkeys (WebAuthn) with the browser's own navigator.credentials API.
// The server sends the options as JSON with binary members base64url-encoded; the browser needs ArrayBuffers. The answer goes
// back in the same JSON form (the shape of PublicKeyCredential.toJSON(), built by hand for browsers that lack it).

type Json = string | number | boolean | null | Json[] | { [key: string]: Json };
type JsonObject = { [key: string]: Json };

/** base64url without padding (RFC 4648 §5), as WebAuthn uses. */
export function base64UrlEncode(data: ArrayBuffer | ArrayBufferView): string {
  const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decodes base64url (padding optional). Throws on characters outside the alphabet. */
export function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(value)) throw new Error('Invalid base64url value.');
  const base64 = value.replace(/=+$/, '').replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '='));
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Whether this browser offers WebAuthn at all (it also needs a secure origin, which the server checks). */
export function webAuthnSupported(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function' && !!navigator.credentials;
}

/** Drops null members: the options are WebIDL dictionaries, where an explicit null is an error for most members. */
export function withoutNulls<T extends Json>(value: T): T {
  if (Array.isArray(value)) return value.map((v) => withoutNulls(v)) as T;
  if (value && typeof value === 'object') {
    const out: JsonObject = {};
    for (const [k, v] of Object.entries(value)) if (v !== null && v !== undefined) out[k] = withoutNulls(v);
    return out as T;
  }
  return value;
}

function descriptors(list: Json | undefined): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return list.map((d) => {
    const o = d as JsonObject;
    return { ...(o as object), type: 'public-key', id: base64UrlDecode(String(o.id)) } as unknown as PublicKeyCredentialDescriptor;
  });
}

/** Server JSON → options for navigator.credentials.create(). */
export function toCreationOptions(json: JsonObject): PublicKeyCredentialCreationOptions {
  const o = withoutNulls(json);
  const user = o.user as JsonObject;
  return {
    ...(o as object),
    challenge: base64UrlDecode(String(o.challenge)),
    user: { ...(user as object), id: base64UrlDecode(String(user.id)) } as unknown as PublicKeyCredentialUserEntity,
    excludeCredentials: descriptors(o.excludeCredentials),
  } as unknown as PublicKeyCredentialCreationOptions;
}

/** Server JSON → options for navigator.credentials.get(). */
export function toRequestOptions(json: JsonObject): PublicKeyCredentialRequestOptions {
  const o = withoutNulls(json);
  return {
    ...(o as object),
    challenge: base64UrlDecode(String(o.challenge)),
    allowCredentials: descriptors(o.allowCredentials),
  } as unknown as PublicKeyCredentialRequestOptions;
}

/** The parts of a PublicKeyCredential this module reads (lets tests pass a plain object). */
export interface CredentialLike {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  authenticatorAttachment?: string | null;
  response: {
    clientDataJSON: ArrayBuffer;
    attestationObject?: ArrayBuffer;
    getTransports?: () => string[];
    authenticatorData?: ArrayBuffer;
    signature?: ArrayBuffer;
    userHandle?: ArrayBuffer | null;
  };
  getClientExtensionResults: () => AuthenticationExtensionsClientOutputs;
}

/** A registration or assertion in the JSON form the server expects. */
export function credentialToJson(credential: CredentialLike): JsonObject {
  const r = credential.response;
  const response: JsonObject = { clientDataJSON: base64UrlEncode(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = base64UrlEncode(r.attestationObject);
    response.transports = typeof r.getTransports === 'function' ? r.getTransports() : [];
  }
  if (r.authenticatorData) response.authenticatorData = base64UrlEncode(r.authenticatorData);
  if (r.signature) response.signature = base64UrlEncode(r.signature);
  if (r.userHandle) response.userHandle = base64UrlEncode(r.userHandle);
  const extensions = credential.getClientExtensionResults() as { credProps?: { rk?: boolean } };
  const clientExtensionResults: JsonObject = {};
  if (extensions.credProps && typeof extensions.credProps.rk === 'boolean') clientExtensionResults.credProps = { rk: extensions.credProps.rk };
  const json: JsonObject = {
    id: credential.id,
    rawId: base64UrlEncode(credential.rawId),
    type: credential.type,
    response,
    clientExtensionResults,
  };
  if (credential.authenticatorAttachment) json.authenticatorAttachment = credential.authenticatorAttachment;
  return json;
}

/** A plain-language message for the browser's WebAuthn errors (the user cancelled, timed out, or used the wrong key). */
export function webAuthnErrorMessage(error: unknown): string | null {
  const name = typeof error === 'object' && error !== null && 'name' in error ? String((error as { name: unknown }).name) : '';
  switch (name) {
    case 'NotAllowedError':
      return 'The request was cancelled or timed out. Try again.';
    case 'InvalidStateError':
      return 'This security key or passkey is already registered to your account.';
    case 'SecurityError':
      return 'The browser refused the request for this address. Passkeys need the console’s DNS name and a trusted certificate.';
    case 'NotSupportedError':
      return 'This browser or security key does not support what the server asked for.';
    case 'AbortError':
      return 'The request was cancelled.';
    default:
      return null;
  }
}

async function friendly<T>(action: () => Promise<T>): Promise<T> {
  try {
    return await action();
  } catch (error) {
    const message = webAuthnErrorMessage(error);
    throw message ? new Error(message) : error;
  }
}

/** Runs navigator.credentials.create() with the server's options and returns the answer as JSON. */
export function createCredential(optionsJson: JsonObject): Promise<JsonObject> {
  return friendly(async () => {
    const credential = await navigator.credentials.create({ publicKey: toCreationOptions(optionsJson) });
    if (!credential) throw new Error('No credential was created.');
    return credentialToJson(credential as unknown as CredentialLike);
  });
}

/** Runs navigator.credentials.get() with the server's options and returns the answer as JSON. */
export function getAssertion(optionsJson: JsonObject): Promise<JsonObject> {
  return friendly(async () => {
    const credential = await navigator.credentials.get({ publicKey: toRequestOptions(optionsJson) });
    if (!credential) throw new Error('No security key or passkey answered.');
    return credentialToJson(credential as unknown as CredentialLike);
  });
}

export type { JsonObject as WebAuthnJson };
