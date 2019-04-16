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

export interface Contents {
  metadata: Metadata;
  payload: Payload;
}

export interface Stringify {
  (metadata: Metadata, payload: Payload, peerPublicKey?: PeerPublicKey): string;
}

export interface Parse {
  (token: string, peerPublicKey?: PeerPublicKey): Contents;
}

export interface PeerPublicKey {
  kid: string;
  publicKey: Uint8Array;
  iss?: string;
}

export const SUPPORTED_BWT_VERSIONS: string[] = ["BWTv0"];
export const SECRET_KEY_BYTES: number = 32;
export const PUBLIC_KEY_BYTES: number = 32;

const SHARED_KEY_BYTES: number = 32;
const CURVE25519: Curve25519 = new Curve25519();
const enc: TextEncoder = new TextEncoder();
const dec: TextDecoder = new TextDecoder();

function* createNonceGenerator(): Generator {
  let base: bigint = BigInt(String(Date.now()).slice(-NONCE_BYTES));
  while (true) {
    yield enc.encode(String(++base));
  }
}

function findPeerPublicKey(
  peerPublicKeys: PeerPublicKey[],
  kid: string
): PeerPublicKey {
  return (
    peerPublicKeys.find(
      (peerPublicKey: PeerPublicKey) => peerPublicKey.kid === kid
    ) || null
  );
}

function isValidMetadata(metadata: any, checkExpiry: boolean = true): boolean {
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

function isValidPeerPublicKey(peerPublicKey: PeerPublicKey): boolean {
  return (
    peerPublicKey &&
    peerPublicKey.kid.length &&
    peerPublicKey.publicKey instanceof Uint8Array &&
    peerPublicKey.publicKey.length === PUBLIC_KEY_BYTES
  );
}

function isValidAudience(aud: string): boolean {
  return !!aud;
}

function isValidToken(token: string): boolean {
  return !!token; // enforce some plausible min length
}

export function stringifier(
  ownSecretKey: Uint8Array,
  peerPublicKey?: PeerPublicKey
): Stringify {
  let sharedKey: Uint8Array;
  if (
    !ownSecretKey ||
    ownSecretKey.length !== SECRET_KEY_BYTES ||
    (peerPublicKey && !isValidPeerPublicKey(peerPublicKey))
  ) {
    return null;
  } else if (peerPublicKey) {
    sharedKey = CURVE25519.scalarMult(ownSecretKey, peerPublicKey.publicKey);
  }
  const nonceGenerator: Generator = createNonceGenerator();
  return function stringify(
    metadata: Metadata,
    payload: Payload,
    peerPublicKey?: PeerPublicKey
  ): string {
    if (peerPublicKey && !isValidPeerPublicKey(peerPublicKey)) {
      return null;
    } else if (peerPublicKey) {
      sharedKey = CURVE25519.scalarMult(ownSecretKey, peerPublicKey.publicKey);
    }
    if (
      !sharedKey ||
      sharedKey.length !== SHARED_KEY_BYTES ||
      !payload ||
      !isValidMetadata(metadata, false)
    ) {
      return null;
    }
    let nonce: Uint8Array;
    let metadataPlusNonce: { [key: string]: any };
    let aad: Uint8Array;
    let plaintext: Uint8Array;
    let aead: { ciphertext: Uint8Array; tag: Uint8Array };
    let head: string, body: string, tail: string;
    try {
      nonce = nonceGenerator.next().value;
      metadataPlusNonce = Object.assign({}, metadata, {
        nonce: Array.from(nonce)
      });
      aad = enc.encode(JSON.stringify(metadataPlusNonce));
      plaintext = enc.encode(JSON.stringify(payload));
      aead = aeadChaCha20Poly1305Seal(sharedKey, nonce, plaintext, aad);
      head = base64FromUint8Array(aad);
      body = base64FromUint8Array(aead.ciphertext);
      tail = base64FromUint8Array(aead.tag);
    } catch (_) {
      return null;
    }
    return `${head}.${body}.${tail}`;
  };
}

export function parser(
  aud: string,
  ownSecretKey: Uint8Array,
  ...cachedPeerPublicKeys: PeerPublicKey[]
): Parse {
  let sharedKey: Uint8Array;
  if (
    !isValidAudience(aud) ||
    !ownSecretKey ||
    ownSecretKey.length !== SECRET_KEY_BYTES ||
    !cachedPeerPublicKeys.every(isValidPeerPublicKey)
  ) {
    return null;
  }
  return function parse(
    token: string,
    ...peerPublicKeys: PeerPublicKey[]
  ): Contents {
    let peerPublicKeySet: PeerPublicKey[];
    if (
      !isValidToken(token) ||
      (peerPublicKeys && !peerPublicKeys.every(isValidPeerPublicKey))
    ) {
      return null;
    } else if (peerPublicKeys.length) {
      peerPublicKeySet = peerPublicKeys;
    } else if (cachedPeerPublicKeys.length) {
      peerPublicKeySet = cachedPeerPublicKeys;
    } else {
      return null;
    }
    let peerPublicKey: PeerPublicKey;
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
      peerPublicKey = findPeerPublicKey(
        peerPublicKeySet,
        metadataPlusNonce.kid
      );
      sharedKey = CURVE25519.scalarMult(ownSecretKey, peerPublicKey.publicKey);
      ciphertext = base64ToUint8Array(parts[1]);
      tag = base64ToUint8Array(parts[2]);
      plaintext = aeadChaCha20Poly1305Open(
        sharedKey,
        Uint8Array.from(metadataPlusNonce.nonce),
        ciphertext,
        aad,
        tag
      );
      payload = JSON.parse(dec.decode(plaintext));
    } catch (_) {
      return null;
    }
    if (
      !payload ||
      !isValidMetadata(metadataPlusNonce, true) ||
      metadataPlusNonce.aud !== aud
    ) {
      return null;
    }
    delete metadataPlusNonce.nonce;
    return { metadata: metadataPlusNonce as Metadata, payload };
  };
}
