import {
  seal as aeadChaCha20Poly1305Seal,
  open as aeadChaCha20Poly1305Open,
  NONCE_BYTES,
  TAG_BYTES
} from "https://denopkg.com/chiefbiiko/aead-chacha20-poly1305/mod.ts";
import { constantTimeEqual } from  "https://denopkg.com/chiefbiiko/aead-chacha20-poly1305/constant_time_equal/constant_time_equal.ts";
import { Curve25519 } from "https://denopkg.com/chiefbiiko/curve25519/mod.ts";
import {
  toUint8Array as base64ToUint8Array,
  fromUint8Array as base64FromUint8Array
} from "https://denopkg.com/chiefbiiko/base64/mod.ts";

export interface Payload {
  [key: string]: unknown;
}

export interface Authenticator {
  stringify(payload: Payload): string;
  parse(token: string): Payload;
}

export interface Curve25519Keys {
  ownSecretKey: Uint8Array;
  peerPublicKey: Uint8Array;
}

export const MAGIC_BUF: Uint8Array = Uint8Array.from([0x42, 0x57, 0x54, 0x31]);
export const SECRET_KEY_BYTES: number = 32;
export const PUBLIC_KEY_BYTES: number = 32;

const CURVE25519: Curve25519 = new Curve25519();
const enc: TextEncoder = new TextEncoder();
const dec: TextDecoder = new TextDecoder();
const MAGIC_BYTES: number = 4;
const MAGIC_NONCE_BYTES: number = MAGIC_BUF.length + NONCE_BYTES;
const MAGIC_NONCE_TAG_BYTES: number = MAGIC_BUF.length + NONCE_BYTES + TAG_BYTES;

function nextNonce(): Uint8Array {
  return enc.encode(String(Date.now()).slice(-12));
}

// TODO: 
//   think about code usage patterns & whether caching the key in the factory
//   makes sense
//     -> createSealer({ sk, pk }), Sealer#stringify(payload)
//     -> createOpener({ sk }), Opener#parse(token)

export function createAuthenticator({
  ownSecretKey,
  peerPublicKey
}: Curve25519Keys): Authenticator {
  if (ownSecretKey.length !== SECRET_KEY_BYTES || peerPublicKey.length !== PUBLIC_KEY_BYTES) {
    return null;
  }
  const key: Uint8Array = CURVE25519.scalarMult(ownSecretKey, peerPublicKey);
  if (key.length !== 32) {
    return null;
  }
  return {
    stringify(payload: Payload): string {
      if (
        !payload ||
        typeof payload.exp !== "number" ||
        Number.isNaN(payload.exp) ||
        !Number.isFinite(payload.exp)
      ) {
        return null;
      }
      const nonce: Uint8Array = nextNonce();
      const plaintext: Uint8Array = enc.encode(JSON.stringify(payload));
      const { ciphertext, tag } = aeadChaCha20Poly1305Seal(
        key,
        nonce,
        plaintext,
        nonce
      );
      const pac: Uint8Array = new Uint8Array(
        MAGIC_NONCE_TAG_BYTES + ciphertext.length
      );
      pac.set(MAGIC_BUF, 0);
      pac.set(nonce, MAGIC_BYTES);
      pac.set(tag, MAGIC_NONCE_BYTES);
      pac.set(ciphertext, MAGIC_NONCE_TAG_BYTES);
      return base64FromUint8Array(pac);
    },
    parse(token: string): Payload {
      const rebased: Uint8Array = base64ToUint8Array(token);
      const magic: Uint8Array = rebased.subarray(0, MAGIC_BYTES);
      const nonce: Uint8Array = rebased.subarray(MAGIC_BYTES, MAGIC_NONCE_BYTES);
      const tag: Uint8Array = rebased.subarray(MAGIC_NONCE_BYTES, MAGIC_NONCE_TAG_BYTES);
      const ciphertext: Uint8Array = rebased.subarray(
        MAGIC_NONCE_TAG_BYTES,
        rebased.length
      );
      if (magic.length !== MAGIC_BYTES || nonce.length !== NONCE_BYTES || tag.length !== TAG_BYTES || !constantTimeEqual(magic, MAGIC_BUF)) {
        return null;
      }
      const plaintext: Uint8Array = aeadChaCha20Poly1305Open(
        key,
        nonce,
        ciphertext,
        nonce,
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
      if (
        !payload ||
        typeof payload.exp !== "number" ||
        Number.isNaN(payload.exp) ||
        !Number.isFinite(payload.exp) ||
        Date.now() > payload.exp
      ) {
        return null;
      }
      return payload;
    }
  };
}
