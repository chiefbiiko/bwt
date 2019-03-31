import {
  aeadChaCha20Poly1305Seal,
  aeadChaCha20Poly1305Open,
  NONCE_BYTES,
  TAG_BYTES
} from "https://denopkg.com/chiefbiiko/aead-chacha20-poly1305/aead_chacha20_poly1305.ts";
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

const CURVE25519: Curve25519 = new Curve25519();
const enc: TextEncoder = new TextEncoder();
const dec: TextDecoder = new TextDecoder();
const NONCE_TAG_BYTES: number = NONCE_BYTES + TAG_BYTES;

function nextNonce(): Uint8Array {
  return enc.encode(String(Date.now()).slice(-12));
}

// TODO: 
// + add required versioned type field. "typ": "BWTv1"
// + import from aead*mod.ts seal, open
// + export SECRET_KEY_BYTES and PUBLIC_KEY_BYTES from module curve25519
// + then validate curve25519 key lengths
// + change payload === null condition to !payload
// + make sure shared key has 256 bits, while within the factory still

export function createAuthenticator({
  ownSecretKey,
  peerPublicKey
}: Curve25519Keys): Authenticator {
  const key: Uint8Array = CURVE25519.scalarMult(ownSecretKey, peerPublicKey);
  return {
    stringify(payload: Payload): string {
      if (
        payload === null ||
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
        NONCE_TAG_BYTES + ciphertext.length
      );
      pac.set(nonce, 0);
      pac.set(tag, NONCE_BYTES);
      pac.set(ciphertext, NONCE_TAG_BYTES);
      return base64FromUint8Array(pac);
    },
    parse(token: string): Payload {
      const rebased: Uint8Array = base64ToUint8Array(token);
      const nonce: Uint8Array = rebased.subarray(0, NONCE_BYTES);
      const tag: Uint8Array = rebased.subarray(NONCE_BYTES, NONCE_TAG_BYTES);
      const ciphertext: Uint8Array = rebased.subarray(
        NONCE_TAG_BYTES,
        rebased.length
      );
      if (nonce.length !== NONCE_BYTES || tag.length !== TAG_BYTES) {
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
        payload === null ||
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
