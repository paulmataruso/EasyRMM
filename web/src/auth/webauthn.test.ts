import { afterEach, describe, expect, it, vi } from "vitest";
import { createKey, creationOptions, credentialJSON, fromBase64url, getKey, KeyCancelled, keyAvailability, requestOptions, toBase64url } from "./webauthn";
import { fakeAssertion, fakeAttestation, stubWebAuthn } from "../test/webauthn";

const bytes = (b: ArrayBuffer | BufferSource | undefined) => Array.from(new Uint8Array(b as ArrayBuffer));

afterEach(() => vi.unstubAllGlobals());

describe("base64url", () => {
  it("round-trips bytes without padding, in the URL-safe alphabet", () => {
    const raw = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const text = toBase64url(raw);
    expect(text).toBe("AAEC-vv8_f7_");
    expect(bytes(fromBase64url(text))).toEqual(Array.from(raw));
    expect(toBase64url(raw.buffer)).toBe(text);
    expect(bytes(fromBase64url("AQ"))).toEqual([1]);
    expect(toBase64url(new Uint8Array(raw.buffer, 3, 2))).toBe(toBase64url(new Uint8Array([250, 251])));
  });
});

describe("keyAvailability", () => {
  it("needs the server, the browser and the right address", () => {
    expect(keyAvailability(undefined)).toMatchObject({ usable: false, why: "server" });
    expect(keyAvailability({ available: false, reason: "Needs a name." })).toEqual({ usable: false, why: "server", message: "Needs a name." });
    expect(keyAvailability({ available: true, origin: window.location.origin })).toMatchObject({ usable: false, why: "browser" });
    stubWebAuthn();
    expect(keyAvailability({ available: true, origin: window.location.origin })).toEqual({ usable: true });
    expect(keyAvailability({ available: true, origin: "https://rmm.example.com" })).toEqual({
      usable: false,
      why: "address",
      origin: "https://rmm.example.com",
      message: "Security keys and passkeys work only at https://rmm.example.com.",
    });
  });
});

describe("options", () => {
  it("decodes the binary fields of registration options", () => {
    const o = creationOptions({
      publicKey: {
        challenge: "AQID",
        rp: { id: "rmm.example.com", name: "EasyRMM" },
        user: { id: "BAUG", name: "alex@example.com", displayName: "Alex" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: [{ type: "public-key", id: "Bwg", transports: ["usb"] }],
      },
    }).publicKey!;
    expect(bytes(o.challenge)).toEqual([1, 2, 3]);
    expect(bytes(o.user.id)).toEqual([4, 5, 6]);
    expect(o.user.name).toBe("alex@example.com");
    expect(o.rp.id).toBe("rmm.example.com");
    expect(bytes(o.excludeCredentials![0]!.id)).toEqual([7, 8]);
    expect(o.excludeCredentials![0]!.transports).toEqual(["usb"]);
  });

  it("decodes the binary fields of sign-in options", () => {
    const o = requestOptions({
      publicKey: { challenge: "AQID", rpId: "rmm.example.com", allowCredentials: [{ type: "public-key", id: "Bwg" }], userVerification: "discouraged" },
    }).publicKey!;
    expect(bytes(o.challenge)).toEqual([1, 2, 3]);
    expect(bytes(o.allowCredentials![0]!.id)).toEqual([7, 8]);
    expect(o.userVerification).toBe("discouraged");
    // Passkey sign-in names no credentials.
    expect(requestOptions({ publicKey: { challenge: "AQID" } }).publicKey!.allowCredentials).toBeUndefined();
  });

  it("refuses options without a challenge", () => {
    expect(() => requestOptions({})).toThrow("incomplete");
    expect(() => creationOptions(null)).toThrow("incomplete");
  });
});

describe("credentialJSON", () => {
  it("encodes a new credential", () => {
    expect(credentialJSON(fakeAttestation())).toEqual({
      id: "cred-1",
      rawId: "AQID",
      type: "public-key",
      authenticatorAttachment: "cross-platform",
      clientExtensionResults: {},
      response: { clientDataJSON: "e30", attestationObject: "o2Nm", transports: ["usb", "nfc"] },
    });
  });

  it("encodes a sign-in answer, with the user handle when there is one", () => {
    expect(credentialJSON(fakeAssertion()).response).toEqual({ clientDataJSON: "e30", authenticatorData: "SZYN", signature: "MEUC", userHandle: "dXNlcg" });
    expect(credentialJSON(fakeAssertion({ userHandle: null })).response).not.toHaveProperty("userHandle");
  });
});

describe("browser errors", () => {
  const dom = (name: string) => new DOMException("browser says no", name);

  it("treats a closed or timed-out prompt as a cancel", async () => {
    const creds = stubWebAuthn();
    creds.get.mockRejectedValueOnce(dom("NotAllowedError"));
    await expect(getKey({ publicKey: { challenge: "AQID" } })).rejects.toBeInstanceOf(KeyCancelled);
    creds.get.mockRejectedValueOnce(dom("AbortError"));
    await expect(getKey({ publicKey: { challenge: "AQID" } })).rejects.toBeInstanceOf(KeyCancelled);
    creds.get.mockResolvedValueOnce(null);
    await expect(getKey({ publicKey: { challenge: "AQID" } })).rejects.toBeInstanceOf(KeyCancelled);
    creds.create.mockResolvedValueOnce(null);
    await expect(createKey({ publicKey: { challenge: "AQID", user: { id: "AQ" } } })).rejects.toBeInstanceOf(KeyCancelled);
  });

  it("explains the rest", async () => {
    const creds = stubWebAuthn();
    const opts = { publicKey: { challenge: "AQID", user: { id: "AQ" } } };
    const cases: [string, string][] = [
      ["InvalidStateError", "already registered to your account"],
      ["SecurityError", "does not match EasyRMM's public address"],
      ["NotSupportedError", "cannot do what EasyRMM asked for"],
      ["UnknownError", "did not respond"],
    ];
    for (const [name, text] of cases) {
      creds.create.mockRejectedValueOnce(dom(name));
      await expect(createKey(opts)).rejects.toThrow(text);
    }
    creds.get.mockRejectedValueOnce(dom("InvalidStateError"));
    await expect(getKey(opts)).rejects.toThrow("could not be used");
    creds.get.mockRejectedValueOnce("not an error");
    await expect(getKey(opts)).rejects.toThrow("did not respond");
  });

  it("returns what the browser created", async () => {
    const creds = stubWebAuthn();
    creds.create.mockResolvedValueOnce(fakeAttestation());
    expect(await createKey({ publicKey: { challenge: "AQID", user: { id: "AQ" } } })).toMatchObject({ id: "cred-1", rawId: "AQID" });
    expect(bytes(creds.create.mock.calls[0]![0].publicKey.challenge)).toEqual([1, 2, 3]);
  });
});
