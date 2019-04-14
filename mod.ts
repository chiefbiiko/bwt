import { Curve25519 } from "https://denopkg.com/chiefbiiko/curve25519/mod.ts";
import {
  toUint8Array as base64ToUint8Array,
  fromUint8Array as base64FromUint8Array
} from "https://denopkg.com/chiefbiiko/base64/mod.ts";
import {
  seal as aeadChaCha20Poly1305Seal,
  open as aeadChaCha20Poly1305Open,
  NONCE_BYTES
} from "https://denopkg.com/chiefbiiko/aead-chacha20-poly1305/mod.ts";

export interface Metadata {
  typ: string;
  iss: string;
  aud: string;
  kid: string;
  iat: number;
  exp: number;
}

export interface Payload {
  [key: string]: unknown;
}

export interface Authenticator {
  stringify(metadata: Metadata, payload: Payload): string;
  parse(token: string): { metadata: Metadata; payload: Payload };
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
  return enc.encode(String(Date.now()).slice(-NONCE_BYTES));
}

// TODO:
//   + think about code usage patterns & whether caching the key in the factory
//     makes sense
//       -> stringifier({
//            ownSecretKey
//            [, peerPublicKey] // { [kid]: { iss, pk } }
//          }): stringify(metadata, payload[, peerPublicKey])
//       -> parser({
//            ownSecretKey
//            peerPublicKeys // { [kidA]: { issA, pkA }, [kidB]: { issB, pkB } }
//          }): parse(token)
//   + make standalone stringify and parse
//   + interface PublicKeyMap
//   + implement bwt key map feature
//   + implement a better default nonce gen func
//   + revisit and polish all dependencies

function isValidMetadata(
  metadata: any,
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
      let nonce: Uint8Array;
      let metadataPlusNonce: { [key: string]: any };
      let aad: Uint8Array;
      let plaintext: Uint8Array;
      let aead: { ciphertext: Uint8Array; tag: Uint8Array };
      let head: string, body: string, tail: string;
      try {
        nonce = nextNonce();
        metadataPlusNonce = Object.assign({}, metadata, {
          nonce: Array.from(nonce)
        });
        aad = enc.encode(JSON.stringify(metadataPlusNonce));
        plaintext = enc.encode(JSON.stringify(payload));
        aead = aeadChaCha20Poly1305Seal(key, nonce, plaintext, aad);
        head = base64FromUint8Array(aad);
        body = base64FromUint8Array(aead.ciphertext);
        tail = base64FromUint8Array(aead.tag);
        return `${head}.${body}.${tail}`;
      } catch (_) {
        return null;
      }
    },
    parse(token: string): { metadata: Metadata; payload: Payload } {
      let parts: string[];
      let aad: Uint8Array;
      let metadataPlusNonce: { [key: string]: any };
      let ciphertext: Uint8Array;
      let tag: Uint8Array;
      let plaintext: Uint8Array;
      let payload: Payload;
      try {
        parts = token.split(".");
        aad = base64ToUint8Array(parts[0]);
        metadataPlusNonce = JSON.parse(dec.decode(aad));
        ciphertext = base64ToUint8Array(parts[1]);
        tag = base64ToUint8Array(parts[2]);
        plaintext = aeadChaCha20Poly1305Open(
          key,
          Uint8Array.from(metadataPlusNonce.nonce),
          ciphertext,
          aad,
          tag
        );
        payload = JSON.parse(dec.decode(plaintext));
      } catch (_) {
        return null;
      }
      if (!payload || !isValidMetadata(metadataPlusNonce, true)) {
        return null;
      }
      metadataPlusNonce.nonce = undefined;
      return { metadata: metadataPlusNonce as Metadata, payload };
    }
  };
}
