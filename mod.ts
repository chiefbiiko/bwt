import { Curve25519 } from "https://denopkg.com/chiefbiiko/curve25519/mod.ts";
import {
  toUint8Array,
  fromUint8Array
} from "https://denopkg.com/chiefbiiko/base64/mod.ts";
import {
  seal,
  open,
  NONCE_BYTES
} from "https://denopkg.com/chiefbiiko/aead-chacha20-poly1305/mod.ts";

export interface Metadata {
  typ: string;
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

// TODO: convert internal peer public keys to map in parse factory

function* createNonceGenerator(): Generator {
  let base: bigint = BigInt(String(Date.now()).slice(-NONCE_BYTES));
  for (;;) {
    yield enc.encode(String(++base));
  }
}

function peerPublicKeysToMap(
  peerPublicKeys: PeerPublicKey[]
): Map<string, Uint8Array> {
  const map: Map<string, Uint8Array> = new Map<string, Uint8Array>();
  for (const peerPublicKey of peerPublicKeys) {
    map.set(peerPublicKey.kid, peerPublicKey.publicKey);
  }
  return map;
}

function assembleMetadataAndNonce(
  metadata: Metadata,
  nonce: Uint8Array
): { [key: string]: any } {
  return Object.assign({}, metadata, { nonce: Array.from(nonce) });
}

function assembleToken(
  aad: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array
): string {
  return (
    fromUint8Array(aad) +
    "." +
    fromUint8Array(ciphertext) +
    "." +
    fromUint8Array(tag)
  );
}

function isValidMetadata(metadata: any): boolean {
  const now: number = Date.now();
  return (
    metadata &&
    SUPPORTED_BWT_VERSIONS.includes(metadata.typ) &&
    metadata.kid.length &&
    metadata.iat >= 0 &&
    !Number.isNaN(metadata.iat) &&
    Number.isFinite(metadata.iat) &&
    metadata.iat <= now &&
    metadata.exp >= 0 &&
    !Number.isNaN(metadata.exp) &&
    Number.isFinite(metadata.exp) &&
    metadata.exp > now
  );
}

function isValidPeerPublicKey(peerPublicKey: PeerPublicKey): boolean {
  return (
    peerPublicKey &&
    peerPublicKey.kid.length &&
    peerPublicKey.publicKey.length === PUBLIC_KEY_BYTES
  );
}

function isValidToken(token: string): boolean {
  return token && token.length < 4096; // enforce some plausible min length
}

function superDeriveSharedKey(
  secretKey: Uint8Array,
  sharedKeyCache: Map<string, Uint8Array>,
  peerPublicKeyMap: Map<string, Uint8Array>,
  kid: string
): Uint8Array {
  if (sharedKeyCache.has(kid)) {
    return sharedKeyCache.get(kid);
  }
  if (!peerPublicKeyMap.has(kid)) {
    return null;
  }
  const sharedKey: Uint8Array = CURVE25519.scalarMult(
    secretKey,
    peerPublicKeyMap.get(kid)
  );
  return sharedKey;
}

export function stringifier(
  ownSecretKey: Uint8Array,
  peerPublicKey?: PeerPublicKey
): Stringify {
  const nonceGenerator: Generator = createNonceGenerator();
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
      !isValidMetadata(metadata)
    ) {
      return null;
    }
    let nonce: Uint8Array;
    let metadataAndNonce: { [key: string]: any };
    let aad: Uint8Array;
    let plaintext: Uint8Array;
    let sealed: { ciphertext: Uint8Array; tag: Uint8Array };
    let token: string;
    try {
      nonce = nonceGenerator.next().value;
      metadataAndNonce = assembleMetadataAndNonce(metadata, nonce);
      aad = enc.encode(JSON.stringify(metadataAndNonce));
      plaintext = enc.encode(JSON.stringify(payload));
      sealed = seal(sharedKey, nonce, plaintext, aad);
      token = assembleToken(aad, sealed.ciphertext, sealed.tag);
    } catch (_) {
      return null;
    }
    if (!isValidToken(token)) {
      return null;
    }
    return token;
  };
}

export function parser(
  ownSecretKey: Uint8Array,
  ...factoryPeerPublicKeys: PeerPublicKey[]
): Parse {
  if (
    !ownSecretKey ||
    ownSecretKey.length !== SECRET_KEY_BYTES ||
    !factoryPeerPublicKeys.every(isValidPeerPublicKey)
  ) {
    return null;
  }
  const sharedKeyCache: Map<string, Uint8Array> = new Map<string, Uint8Array>();
  const deriveSharedKey: Function = superDeriveSharedKey.bind(
    null,
    ownSecretKey,
    sharedKeyCache
  );
  let peerPublicKeyMap: Map<string, Uint8Array>;
  return function parse(
    token: string,
    ...peerPublicKeys: PeerPublicKey[]
  ): Contents {
    if (!isValidToken(token) || !peerPublicKeys.every(isValidPeerPublicKey)) {
      return null;
    } else if (peerPublicKeys.length) {
      peerPublicKeyMap = peerPublicKeysToMap(peerPublicKeys);
    } else if (factoryPeerPublicKeys.length) {
      peerPublicKeyMap = peerPublicKeysToMap(factoryPeerPublicKeys);
    } else {
      return null;
    }
    let sharedKey: Uint8Array;
    let parts: string[];
    let aad: Uint8Array;
    let metadataAndNonce: { [key: string]: any };
    let nonce: Uint8Array;
    let ciphertext: Uint8Array;
    let tag: Uint8Array;
    let plaintext: Uint8Array;
    let payload: Payload;
    try {
      parts = token.split(".");
      aad = toUint8Array(parts[0]);
      metadataAndNonce = JSON.parse(dec.decode(aad));
      nonce = Uint8Array.from(metadataAndNonce.nonce);
      sharedKey = deriveSharedKey(peerPublicKeyMap, metadataAndNonce.kid);
      ciphertext = toUint8Array(parts[1]);
      tag = toUint8Array(parts[2]);
      plaintext = open(sharedKey, nonce, ciphertext, aad, tag);
      payload = JSON.parse(dec.decode(plaintext));
    } catch (_) {
      return null;
    }
    if (!payload || !isValidMetadata(metadataAndNonce)) {
      return null;
    }
    delete metadataAndNonce.nonce;
    return { metadata: metadataAndNonce as Metadata, payload };
  };
}
