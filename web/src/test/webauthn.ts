// A stand-in for the browser's WebAuthn API: jsdom has none. Tests choose what navigator.credentials answers.

import { vi } from "vitest";

const buf = (...b: number[]) => new Uint8Array(b).buffer;

/** Installs PublicKeyCredential and navigator.credentials; returns the create/get mocks. Undone by vi.unstubAllGlobals. */
export function stubWebAuthn() {
  const credentials = { create: vi.fn(), get: vi.fn() };
  vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
  // Own properties: the prototype's getters (userAgent and the rest) refuse an object that is not jsdom's navigator.
  vi.stubGlobal(
    "navigator",
    Object.create(navigator, { credentials: { value: credentials }, userAgent: { value: navigator.userAgent } }),
  );
  return credentials;
}

/** What navigator.credentials.create() returns for a USB key. */
export function fakeAttestation(): PublicKeyCredential {
  return {
    id: "cred-1",
    rawId: buf(1, 2, 3),
    type: "public-key",
    authenticatorAttachment: "cross-platform",
    getClientExtensionResults: () => ({}),
    response: { clientDataJSON: buf(0x7b, 0x7d), attestationObject: buf(0xa3, 0x63, 0x66), getTransports: () => ["usb", "nfc"] },
  } as unknown as PublicKeyCredential;
}

/** What navigator.credentials.get() returns. */
export function fakeAssertion(over: { userHandle?: ArrayBuffer | null } = {}): PublicKeyCredential {
  return {
    id: "cred-1",
    rawId: buf(1, 2, 3),
    type: "public-key",
    authenticatorAttachment: "cross-platform",
    getClientExtensionResults: () => ({}),
    response: {
      clientDataJSON: buf(0x7b, 0x7d),
      authenticatorData: buf(0x49, 0x96, 0x0d),
      signature: buf(0x30, 0x45, 0x02),
      userHandle: over.userHandle === undefined ? buf(0x75, 0x73, 0x65, 0x72) : over.userHandle,
    },
  } as unknown as PublicKeyCredential;
}

/** Sign-in options whose keys work on the test page. */
export function keysUsableHere() {
  return { passwordResetAvailable: false, mfaRequired: true, passwordMinLength: 12, webauthn: { available: true, origin: window.location.origin } };
}
