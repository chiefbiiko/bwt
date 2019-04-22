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

function* createNonceGenerator(): Generator {
  let base: bigint = BigInt(String(Date.now()).slice(-NONCE_BYTES));
  for (;;) {
    yield enc.encode(String(++base));
  }
}

function toPublicKeyMap(
  ...peerPublicKeys: PeerPublicKey[]
): Map<string, Uint8Array> {
  return new Map<string, Uint8Array>(
    peerPublicKeys.map(
      ({ kid, publicKey }: PeerPublicKey): [string, Uint8Array] => [
        kid,
        publicKey
      ]
    )
  );
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

function isValidMetadata(x: any): boolean {
  const now: number = Date.now();
  return (
    x &&
    SUPPORTED_BWT_VERSIONS.includes(x.typ) &&
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

function isValidSharedKey(x: Uint8Array): boolean {
  return x && x.length === SHARED_KEY_BYTES;
}

function isValidSecretKey(x: Uint8Array): boolean {
  return x && x.length === SECRET_KEY_BYTES;
}

function isValidPeerPublicKey(x: PeerPublicKey): boolean {
  return x && x.kid.length && x.publicKey.length === PUBLIC_KEY_BYTES;
}

function isValidToken(x: string): boolean {
  return x && x.length < 4096; // enforce some plausible min length
}

function deriveSharedKeyProto(
  secretKey: Uint8Array,
  sharedKeyCache: Map<string, Uint8Array>,
  factoryPublicKeyMap: Map<string, Uint8Array>,
  kid: string,
  ...peerPublicKeySpace: PeerPublicKey[]
): Uint8Array {
  let publicKey: Uint8Array;
  if (peerPublicKeySpace.length && sharedKeyCache.has(kid)) {
    return sharedKeyCache.get(kid);
  } else if (peerPublicKeySpace.length && kid) {
    let peerPublicKey: PeerPublicKey = peerPublicKeySpace.find(
      ({ kid: _kid }: PeerPublicKey): boolean => _kid === kid
    );
    publicKey = peerPublicKey ? peerPublicKey.publicKey : null;
  } else if (sharedKeyCache.has(kid)) {
    return sharedKeyCache.get(kid);
  } else if (factoryPublicKeyMap.has(kid)) {
    publicKey = factoryPublicKeyMap.get(kid);
  }
  if (!publicKey) {
    return null;
  }
  const sharedKey: Uint8Array = CURVE25519.scalarMult(secretKey, publicKey);
  sharedKeyCache.set(kid, sharedKey);
  return sharedKey;
}

// TODO: BWT.generateKeys(seed?): { sk, pk, kid }

export function stringifier(
  ownSecretKey: Uint8Array,
  factoryPeerPublicKey?: PeerPublicKey
): Stringify {
  if (
    !isValidSecretKey(ownSecretKey) ||
    (factoryPeerPublicKey && !isValidPeerPublicKey(factoryPeerPublicKey))
  ) {
    return null;
  }
  const nonceGenerator: Generator = createNonceGenerator();
  const deriveSharedKey: Function = deriveSharedKeyProto.bind(
    null,
    ownSecretKey,
    new Map<string, Uint8Array>(),
    toPublicKeyMap(factoryPeerPublicKey)
  );
  return function stringify(
    metadata: Metadata,
    payload: Payload,
    peerPublicKey?: PeerPublicKey
  ): string {
    if (
      !isValidMetadata(metadata) ||
      !payload ||
      (peerPublicKey && !isValidPeerPublicKey(peerPublicKey))
    ) {
      return null;
    }
    let sharedKey: Uint8Array;
    let nonce: Uint8Array;
    let metadataAndNonce: { [key: string]: any };
    let aad: Uint8Array;
    let plaintext: Uint8Array;
    let sealed: { ciphertext: Uint8Array; tag: Uint8Array };
    let token: string;
    try {
      if (peerPublicKey) {
        sharedKey = deriveSharedKey(peerPublicKey.kid, peerPublicKey);
      } else if (factoryPeerPublicKey) {
        sharedKey = deriveSharedKey(factoryPeerPublicKey.kid);
      }
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
    !isValidSecretKey(ownSecretKey) ||
    !factoryPeerPublicKeys.every(isValidPeerPublicKey)
  ) {
    return null;
  }
  const deriveSharedKey: Function = deriveSharedKeyProto.bind(
    null,
    ownSecretKey,
    new Map<string, Uint8Array>(),
    toPublicKeyMap(...factoryPeerPublicKeys)
  );
  return function parse(
    token: string,
    ...peerPublicKeys: PeerPublicKey[]
  ): Contents {
    if (!isValidToken(token) || !peerPublicKeys.every(isValidPeerPublicKey)) {
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
      sharedKey = deriveSharedKey(metadataAndNonce.kid, ...peerPublicKeys);
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
