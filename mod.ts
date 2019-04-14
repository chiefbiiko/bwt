import {
  seal as aeadChaCha20Poly1305Seal,
  open as aeadChaCha20Poly1305Open,
  NONCE_BYTES,
  TAG_BYTES
} from "https://denopkg.com/chiefbiiko/aead-chacha20-poly1305/mod.ts";
import { constantTimeEqual } from "https://denopkg.com/chiefbiiko/aead-chacha20-poly1305/constant_time_equal/constant_time_equal.ts";
import { Curve25519 } from "https://denopkg.com/chiefbiiko/curve25519/mod.ts";
import {
  toUint8Array as base64ToUint8Array,
  fromUint8Array as base64FromUint8Array
} from "https://denopkg.com/chiefbiiko/base64/mod.ts";

export interface Metadata {
  typ: string;
  iss: string;
  aud: string;
  kid: string;
  iat: number;
  exp: number;
}

interface InternalMetadata extends Metadata {
  nonce: Uint8Array;
}

export interface Payload {
  [key: string]: unknown;
}

export interface Authenticator {
  stringify(metadata: Metadata, payload: Payload): string;
  parse(token: string): Payload;
}

export interface Curve25519Keys {
  ownSecretKey: Uint8Array;
  peerPublicKey: Uint8Array;
}

export const SUPPORTED_BWT_VERSIONS: string[] = ["BWTv1"];

export const SECRET_KEY_BYTES: number = 32;
export const PUBLIC_KEY_BYTES: number = 32;
const SHARED_KEY_BYTES: number = 32;

const CURVE25519: Curve25519 = new Curve25519();
const enc: TextEncoder = new TextEncoder();
const dec: TextDecoder = new TextDecoder();

function nextNonce(): Uint8Array {
  return enc.encode(String(Date.now()).slice(-12));
}

// TODO:
//   + catch all JSON* and base64* errors
//   + think about code usage patterns & whether caching the key in the factory
//     makes sense
//       -> createStringify(/**/), stringify(metadata, payload)
//       -> createParse(/**/), parse(token)
//   + make standalone stringify and parse
//   + implement bwt key set feature: Set [{kid:"abc",pk:"xyz"},{/**/}]
//   + revisit and polish all dependencies

function isValidMetadata(
  metadata: Metadata,
  checkExpiry: boolean = true
): boolean {
  return (
    metadata &&
    SUPPORTED_BWT_VERSIONS.includes(metadata.typ) &&
    metadata.iss.length &&
    metadata.aud.length &&
    metadata.kid.length &&
    !Number.isNaN(metadata.iat) &&
    Number.isFinite(metadata.iat) &&
    metadata.iat >= 0 &&
    !Number.isNaN(metadata.exp) &&
    Number.isFinite(metadata.exp) &&
    metadata.exp >= 0 &&
    (checkExpiry ? metadata.exp > Date.now() : true)
  );
}

export function createAuthenticator({
  ownSecretKey,
  peerPublicKey
}: Curve25519Keys): Authenticator {
  if (
    ownSecretKey.length !== SECRET_KEY_BYTES ||
    peerPublicKey.length !== PUBLIC_KEY_BYTES
  ) {
    return null;
  }
  const key: Uint8Array = CURVE25519.scalarMult(ownSecretKey, peerPublicKey);
  if (key.length !== SHARED_KEY_BYTES) {
    return null;
  }
  return {
    stringify(metadata: Metadata, payload: Payload): string {
      if (!payload || !isValidMetadata(metadata, false)) {
        return null;
      }
      const nonce: Uint8Array = nextNonce();
      if (nonce.length !== NONCE_BYTES) {
        return null;
      }
      let aad: Uint8Array;
      let plaintext: Uint8Array;
      let aead: { ciphertext: Uint8Array; tag: Uint8Array };
      try {
        aad = enc.encode(
          JSON.stringify(
            Object.assign({}, metadata, {
              nonce: Array.from(nonce)
            })
          )
        );
        plaintext = enc.encode(JSON.stringify(payload));
        aead = aeadChaCha20Poly1305Seal(key, nonce, plaintext, aad);
      } catch (_) {
        return null;
      }
      return (
        base64FromUint8Array(aad) +
        "." +
        base64FromUint8Array(aead.ciphertext) +
        "." +
        base64FromUint8Array(aead.tag)
      );
    },
    parse(token: string): { metadata: Metadata; payload: Payload } {
      if (!token) {
        return null;
      }
      const parts: string[] = token.split(".");
      if (parts.length !== 3) {
        return null;
      }
      const aad: Uint8Array = base64ToUint8Array(parts[0]);
      const metadata: InternalMetadata = JSON.parse(dec.decode(aad));
      const ciphertext: Uint8Array = base64ToUint8Array(parts[1]);
      const tag: Uint8Array = base64ToUint8Array(parts[2]);
      const plaintext: Uint8Array = aeadChaCha20Poly1305Open(
        key,
        Uint8Array.from(metadata.nonce),
        ciphertext,
        aad,
        tag
      );
      if (!plaintext) {
        return null;
      }
      let payload: Payload;
      try {
        payload = JSON.parse(dec.decode(plaintext));
      } catch (_) {
        return null;
      }
      if (!payload || !isValidMetadata(metadata, true)) {
        return null;
      }
      return { metadata, payload };
    }
  };
}
