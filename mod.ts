import { Curve25519 } from "https://denopkg.com/chiefbiiko/curve25519/mod.ts";

import {
  encode,
  decode
} from "https://denopkg.com/chiefbiiko/std-encoding/mod.ts";

import {
  seal,
  open,
  NONCE_BYTES
} from "https://denopkg.com/chiefbiiko/aead-chacha20-poly1305/mod.ts";

// TODO:
//   keys (KeyPair, PeerPublicKey) have either all bin or base64 fields
//   related functions take an additional encoding parameter
//   !! encode maybe base64-encoded input keys to binary in any exposed funcs !!

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

export interface KeyPair {
  kid: string | Uint8Array;
  pk: string | Uint8Array;
  sk: string | Uint8Array;
}

export interface PeerPublicKey {
  kid: string | Uint8Array;
  pk: string | Uint8Array;
  name?: string | Uint8Array;
}

export const SUPPORTED_BWT_VERSIONS: string[] = ["BWTv0"];
export const SECRET_KEY_BYTES: number = 32;
export const PUBLIC_KEY_BYTES: number = 32;

interface MetadataAndNonce extends Metadata {
  nonce: number[];
}

const CURVE25519: Curve25519 = new Curve25519();
const BASE64: RegExp = /base64/i;

/** Transforms any string to binary props is the key is not "kid". */
function normalizePeerPublicKey(ppk: PeerPublicKey): PeerPublicKey {
  const clone: PeerPublicKey = { ...ppk };

  if (typeof clone.kid !== "string") {
    clone.kid = decode(clone.kid, "base64");
  }

  if (typeof clone.pk === "string") {
    clone.pk = encode(clone.pk);
  }

  return clone;
}

function normalizeMetadata(metadata: Metadata): Metadata {
  const clone: Metadata = { ...metadata } as Metadata;

  if (typeof clone.kid !== "string") {
    clone.kid = decode(clone.kid, "base64");
  }

  return clone;
}

function* createNonceGenerator(): Generator {
  let base: bigint = BigInt(String(Date.now()).slice(-NONCE_BYTES));

  for (;;) {
    yield encode(String(++base), "utf8");
  }
}

function toPublicKeyMap(
  ...peerPublicKeys: PeerPublicKey[]
): Map<string, Uint8Array> {
  const map: Map<string, Uint8Array> = new Map<string, Uint8Array>();

  for (const peerPublicKey of peerPublicKeys) {
    map.set(peerPublicKey.kid as string, peerPublicKey.pk as Uint8Array);
  }

  return map;
}

function assembleMetadataAndNonce(
  metadata: Metadata,
  nonce: Uint8Array
): MetadataAndNonce {
  return { ...metadata, nonce: Array.from(nonce) };
}

function assembleToken(
  aad: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array
): string {
  return (
    decode(aad, "base64") +
    "." +
    decode(ciphertext, "base64") +
    "." +
    decode(tag, "base64")
  );
}

function isValidMetadata(x: any): boolean {
  const now: number = Date.now();
  return (
    x &&
    SUPPORTED_BWT_VERSIONS.includes(x.typ) &&
    x.kid &&
    // TODO: assert length equals 16 bytes
    x.kid.length &&
    x.iat >= 0 &&
    !Number.isNaN(x.iat) &&
    Number.isFinite(x.iat) &&
    x.iat <= now &&
    x.exp >= 0 &&
    !Number.isNaN(x.exp) &&
    Number.isFinite(x.exp) &&
    x.exp > now
  );
}

function isValidSecretKey(x: Uint8Array): boolean {
  return x && x.byteLength === SECRET_KEY_BYTES;
}

function isValidPeerPublicKey(x: PeerPublicKey): boolean {
  return x && x.kid.length && x.pk.length === PUBLIC_KEY_BYTES;
}

function isValidToken(x: string): boolean {
  return x && x.length < 4096; // enforce some plausible min length
}

function deriveSharedKeyProto(
  secretKey: Uint8Array,
  sharedKeyCache: Map<string, Uint8Array>,
  defaultPublicKeyMap: Map<string, Uint8Array>,
  defaultKid: string,
  kid: string = defaultKid,
  ...peerPublicKeySpace: PeerPublicKey[]
): Uint8Array {
  if (sharedKeyCache.has(kid)) {
    return sharedKeyCache.get(kid);
  }

  let publicKey: Uint8Array;

  if (peerPublicKeySpace.length) {
    let peerPublicKey: PeerPublicKey = peerPublicKeySpace.find(
      ({ kid: _kid }: PeerPublicKey): boolean => _kid === kid
    );

    publicKey = peerPublicKey ? (peerPublicKey.pk as Uint8Array) : null;
  } else if (defaultPublicKeyMap.has(kid)) {
    publicKey = defaultPublicKeyMap.get(kid);
  }

  if (!publicKey) {
    return null;
  }

  const sharedKey: Uint8Array = CURVE25519.scalarMult(secretKey, publicKey);
  sharedKeyCache.set(kid, sharedKey);

  return sharedKey;
}

export function generateKeys(outputEncoding?: string): KeyPair {
  if (outputEncoding && !BASE64.test(outputEncoding)) {
    throw new TypeError('outputEncoding must be undefined or "base64"');
  }

  const keypair: { sk: Uint8Array; pk: Uint8Array } = CURVE25519.generateKeys(
    crypto.getRandomValues(new Uint8Array(32))
  );

  const kid: Uint8Array = crypto.getRandomValues(new Uint8Array(16));

  if (outputEncoding) {
    return {
      sk: decode(keypair.sk, "base64"),
      pk: decode(keypair.pk, "base64"),
      kid: decode(kid, "base64")
    };
  }

  return { ...keypair, kid };
}

export function stringifier(
  ownSecretKey: Uint8Array,
  defaultPeerPublicKey?: PeerPublicKey
): Stringify {
  if (defaultPeerPublicKey) {
    defaultPeerPublicKey = normalizePeerPublicKey(defaultPeerPublicKey);
  }

  if (
    !isValidSecretKey(ownSecretKey) ||
    (defaultPeerPublicKey && !isValidPeerPublicKey(defaultPeerPublicKey))
  ) {
    return null;
  }

  const nonceGenerator: Generator = createNonceGenerator();

  const deriveSharedKey: Function = deriveSharedKeyProto.bind(
    null,
    ownSecretKey,
    new Map<string, Uint8Array>(),
    toPublicKeyMap(defaultPeerPublicKey),
    defaultPeerPublicKey ? defaultPeerPublicKey.kid : null
  );

  return function stringify(
    metadata: Metadata,
    payload: Payload,
    peerPublicKey?: PeerPublicKey
  ): string {
    if (metadata) {
      metadata = normalizeMetadata(metadata);
    }

    if (peerPublicKey) {
      peerPublicKey = normalizePeerPublicKey(peerPublicKey);
    }

    if (
      !isValidMetadata(metadata) ||
      !payload ||
      (peerPublicKey && !isValidPeerPublicKey(peerPublicKey))
    ) {
      return null;
    }

    let sharedKey: Uint8Array;
    let nonce: Uint8Array;
    let metadataAndNonce: MetadataAndNonce;
    let aad: Uint8Array;
    let plaintext: Uint8Array;
    let sealed: { ciphertext: Uint8Array; tag: Uint8Array };
    let token: string;

    try {
      sharedKey = deriveSharedKey.apply(
        null,
        peerPublicKey ? [peerPublicKey.kid, peerPublicKey] : []
      );
      nonce = nonceGenerator.next().value;
      metadataAndNonce = assembleMetadataAndNonce(metadata, nonce);
      aad = encode(JSON.stringify(metadataAndNonce), "utf8");
      plaintext = encode(JSON.stringify(payload), "utf8");
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
  ...defaultPeerPublicKeys: PeerPublicKey[]
): Parse {
  if (defaultPeerPublicKeys.length) {
    defaultPeerPublicKeys = defaultPeerPublicKeys.map(normalizePeerPublicKey);
  }

  if (
    !isValidSecretKey(ownSecretKey) ||
    !defaultPeerPublicKeys.every(isValidPeerPublicKey)
  ) {
    return null;
  }

  const deriveSharedKey: Function = deriveSharedKeyProto.bind(
    null,
    ownSecretKey,
    new Map<string, Uint8Array>(),
    toPublicKeyMap(...defaultPeerPublicKeys),
    null
  );

  return function parse(
    token: string,
    ...peerPublicKeys: PeerPublicKey[]
  ): Contents {
    if (peerPublicKeys.length) {
      peerPublicKeys = peerPublicKeys.map(normalizePeerPublicKey);
    }

    if (!isValidToken(token) || !peerPublicKeys.every(isValidPeerPublicKey)) {
      return null;
    }

    let sharedKey: Uint8Array;
    let parts: string[];
    let aad: Uint8Array;
    let metadataAndNonce: MetadataAndNonce;
    let nonce: Uint8Array;
    let ciphertext: Uint8Array;
    let tag: Uint8Array;
    let plaintext: Uint8Array;
    let payload: Payload;

    try {
      parts = token.split(".");
      aad = encode(parts[0], "base64");
      metadataAndNonce = JSON.parse(decode(aad, "utf8"));
      nonce = Uint8Array.from(metadataAndNonce.nonce);
      sharedKey = deriveSharedKey(metadataAndNonce.kid, ...peerPublicKeys);
      ciphertext = encode(parts[1], "base64");
      tag = encode(parts[2], "base64");
      plaintext = open(sharedKey, nonce, ciphertext, aad, tag);
      payload = JSON.parse(decode(plaintext, "utf8"));
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
