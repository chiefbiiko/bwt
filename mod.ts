import {
  aeadChaCha20Poly1305Seal,
  aeadChaCha20Poly1305Open,
  NONCE_BYTES,
  TAG_BYTES
} from "https://denopkg.com/chiefbiiko/aead-chacha20-poly1305/aead_chacha20_poly1305.ts";
import { Curve25519 } from "https://denopkg.com/chiefbiiko/curve25519/mod.ts";
import {
  toUint8Array,
  fromUint8Array
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

const CURVE25519: Curve25519 = new Curve25519();
const enc: TextEncoder = new TextEncoder();
const dec: TextDecoder = new TextDecoder();

function nextNonce(): Uint8Array {
  return enc.encode(String(Date.now()).slice(-12));
}

export function createAuthenticator({
  ownSecretKey,
  peerPublicKey
}: Curve25519Keys): Authenticator {
  const key: Uint8Array = CURVE25519.scalarMult(ownSecretKey, peerPublicKey);
  return {
    stringify(payload: Payload): string {
      const nonce: Uint8Array = nextNonce();
      const plaintext: Uint8Array = enc.encode(JSON.stringify(payload));
      const { ciphertext, tag } = aeadChaCha20Poly1305Seal(
        key,
        nonce,
        plaintext,
        nonce
      );
      const pac: Uint8Array = new Uint8Array(
        NONCE_BYTES + TAG_BYTES + ciphertext.length
      );
      pac.set(nonce, 0);
      pac.set(tag, NONCE_BYTES);
      pac.set(ciphertext, NONCE_BYTES + TAG_BYTES);
      return fromUint8Array(pac);
    },
    parse(token: string): Payload {
      const rebased: Uint8Array = toUint8Array(token);
      const nonce: Uint8Array = rebased.subarray(0, NONCE_BYTES);
      const tag: Uint8Array = rebased.subarray(
        NONCE_BYTES,
        NONCE_BYTES + TAG_BYTES
      );
      const ciphertext: Uint8Array = rebased.subarray(
        NONCE_BYTES + TAG_BYTES,
        rebased.length
      );
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
        typeof payload.exp !== "number" ||
        Number.isNaN(payload.exp) ||
        payload.exp === Infinity ||
        Date.now() > payload.exp
      ) {
        return null;
      }
      return payload;
    }
  };
}
