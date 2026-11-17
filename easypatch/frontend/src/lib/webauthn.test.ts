import { describe, expect, it } from 'vitest';
import {
  base64UrlDecode,
  base64UrlEncode,
  credentialToJson,
  toCreationOptions,
  toRequestOptions,
  webAuthnErrorMessage,
  withoutNulls,
  type CredentialLike,
} from './webauthn';

const bytes = (...values: number[]) => new Uint8Array(values);

describe('base64url', () => {
  it('encodes without padding and with the URL-safe alphabet', () => {
    expect(base64UrlEncode(bytes())).toBe('');
    expect(base64UrlEncode(bytes(0xfb, 0xff))).toBe('-_8');
    expect(base64UrlEncode(bytes(1, 2, 3, 4))).toBe('AQIDBA');
    expect(base64UrlEncode(bytes(1, 2, 3, 4).buffer)).toBe('AQIDBA');
  });
  it('encodes a view into a larger buffer by its own bytes only', () => {
    const view = new Uint8Array(bytes(9, 1, 2, 9).buffer, 1, 2);
    expect(base64UrlEncode(view)).toBe('AQI');
  });
  it('round-trips any bytes, with or without padding', () => {
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect(Array.from(base64UrlDecode(base64UrlEncode(all)))).toEqual(Array.from(all));
    expect(Array.from(base64UrlDecode('AQIDBA=='))).toEqual([1, 2, 3, 4]);
    expect(Array.from(base64UrlDecode('-_8'))).toEqual([0xfb, 0xff]);
  });
  it('rejects standard base64 and other characters', () => {
    expect(() => base64UrlDecode('+/8=')).toThrow();
    expect(() => base64UrlDecode('a b')).toThrow();
  });
});

describe('options', () => {
  it('drops null members recursively', () => {
    expect(withoutNulls({ a: null, b: { c: null, d: 1 }, e: [{ f: null }] })).toEqual({ b: { d: 1 }, e: [{}] });
  });

  it('decodes the challenge, the user handle and excluded credentials for create()', () => {
    const options = toCreationOptions({
      rp: { id: 'patch.example.com', name: 'EasyPatch' },
      user: { id: 'AQID', name: 'jane@example.com', displayName: 'jane' },
      challenge: 'BAUG',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required', authenticatorAttachment: null },
      excludeCredentials: [{ type: 'public-key', id: 'BwgJ', transports: ['usb'] }],
      attestation: 'none',
    });
    expect(Array.from(new Uint8Array(options.challenge as ArrayBuffer))).toEqual([4, 5, 6]);
    expect(Array.from(new Uint8Array(options.user.id as ArrayBuffer))).toEqual([1, 2, 3]);
    expect(options.user.name).toBe('jane@example.com');
    expect(options.rp.id).toBe('patch.example.com');
    expect(options.authenticatorSelection).toEqual({ residentKey: 'required', userVerification: 'required' });
    const excluded = options.excludeCredentials![0];
    expect(Array.from(new Uint8Array(excluded.id as ArrayBuffer))).toEqual([7, 8, 9]);
    expect(excluded.transports).toEqual(['usb']);
  });

  it('decodes the challenge and allowed credentials for get(), and keeps an empty allow list for passkeys', () => {
    const second = toRequestOptions({ challenge: 'AQID', rpId: 'patch.example.com', allowCredentials: [{ type: 'public-key', id: 'BAUG' }], userVerification: 'discouraged' });
    expect(Array.from(new Uint8Array(second.allowCredentials![0].id as ArrayBuffer))).toEqual([4, 5, 6]);
    expect(second.userVerification).toBe('discouraged');
    const passkey = toRequestOptions({ challenge: 'AQID', allowCredentials: [], userVerification: 'required' });
    expect(passkey.allowCredentials).toEqual([]);
  });
});

describe('credentialToJson', () => {
  const buffer = (...values: number[]) => bytes(...values).buffer;

  it('serializes a registration with transports and the credProps result', () => {
    const credential: CredentialLike = {
      id: 'AQI',
      rawId: buffer(1, 2),
      type: 'public-key',
      authenticatorAttachment: 'cross-platform',
      response: { clientDataJSON: buffer(3), attestationObject: buffer(4), getTransports: () => ['usb', 'nfc'] },
      getClientExtensionResults: () => ({ credProps: { rk: true } }),
    };
    expect(credentialToJson(credential)).toEqual({
      id: 'AQI',
      rawId: 'AQI',
      type: 'public-key',
      authenticatorAttachment: 'cross-platform',
      response: { clientDataJSON: 'Aw', attestationObject: 'BA', transports: ['usb', 'nfc'] },
      clientExtensionResults: { credProps: { rk: true } },
    });
  });

  it('serializes an assertion, leaving out a missing user handle', () => {
    const credential: CredentialLike = {
      id: 'AQI',
      rawId: buffer(1, 2),
      type: 'public-key',
      response: { clientDataJSON: buffer(3), authenticatorData: buffer(5), signature: buffer(6), userHandle: null },
      getClientExtensionResults: () => ({}),
    };
    expect(credentialToJson(credential)).toEqual({
      id: 'AQI',
      rawId: 'AQI',
      type: 'public-key',
      response: { clientDataJSON: 'Aw', authenticatorData: 'BQ', signature: 'Bg' },
      clientExtensionResults: {},
    });
  });
});

describe('webAuthnErrorMessage', () => {
  it('explains the browser errors users meet', () => {
    expect(webAuthnErrorMessage(new DOMException('x', 'NotAllowedError'))).toMatch(/cancelled or timed out/);
    expect(webAuthnErrorMessage(new DOMException('x', 'InvalidStateError'))).toMatch(/already registered/);
    expect(webAuthnErrorMessage(new DOMException('x', 'SecurityError'))).toMatch(/DNS name/);
    expect(webAuthnErrorMessage(new Error('other'))).toBeNull();
    expect(webAuthnErrorMessage('text')).toBeNull();
  });
});
