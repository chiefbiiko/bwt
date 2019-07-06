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

/**
 * BWT metadata object.
 * 
 * typ must be a supported BWT version tag, currently that is "BWTv0" only.
 * iat and exp denote the issued-at and expiry ms timestamps of a token.
 * kid is the public key identifier of the issuing party. base64 encoded kid
 * strings are supported.
 */
export interface Metadata {
  typ: string;
  iat: number;
  exp: number;
  kid: string | Uint8Array;
}

/** BWT payload object. */
export interface Payload {
  [key: string]: unknown;
}

/** Parsed contents of a token. */
export interface Contents {
  metadata: Metadata;
  payload: Payload;
}

/** BWT stringify function. */
export interface Stringify {
  (metadata: Metadata, payload: Payload, peerPublicKey?: PeerPublicKey): string;
}

/** BWT parse function. */
export interface Parse {
  (token: string, peerPublicKey?: PeerPublicKey): Contents;
}

/**
 * BWT keypair object including a key identifier for the public key.
 *
 * sk is the 32-byte secret key.
 * pk is the 32-byte public key.
 * kid is a 16-byte key identifer for the public key.
 *
 * Any of the above properties can either be buffers or base64 strings.
*/
export interface KeyPair {
    sk: string | Uint8Array;
  pk: string | Uint8Array;
  kid: string | Uint8Array;
}

/**
 * BWT public key of a peer.
 *
 * pk is the 32-byte public key.
 * kid is a 16-byte key identifer for the public key.
 * name can be an arbitrarily encoded string or a buffer.
 */
export interface PeerPublicKey {
  pk: string | Uint8Array;
    kid: string | Uint8Array;
  name?: string | Uint8Array;
}

/** Supported BWT versions. */
export const SUPPORTED_BWT_VERSIONS: string[] = ["BWTv0"];

/** Byte length of a Curve25519 secret key. */
export const SECRET_KEY_BYTES: number = 32;

/** Byte length of a Curve25519 public key. */
export const PUBLIC_KEY_BYTES: number = 32;

/** Internal object representation adding a nonce to a metadata object. */
interface MetadataAndNonce extends Metadata {
  nonce: number[];
}
/** Global Curve25519 instance provding a scalar multiplication op. */
const CURVE25519: Curve25519 = new Curve25519();

/** One-time-compiled regex for checking outputEncoding params.*/
const BASE64_REGEX: RegExp = /base64/i;

/** Number of characters of a base64 encoded public key identifier. */
const KID_BYTES_BASE64: number = 24;

/** Maximum allowed number of characters of a token. */
const MAX_TOKEN_LENGTH: number = 4096;

/** Transforms any string to binary props if it is not "kid", stays string. */
/**
 * Normalizes a peer pubilc key object by assuring its kid is a base64 string
 * and ensuring that its pk prop is a Uint8Array.
 */
function normalizePeerPublicKey(ppk: PeerPublicKey): PeerPublicKey {
  const clone: PeerPublicKey = { ...ppk };

  if (clone.kid instanceof Uint8Array) {
    clone.kid = decode(clone.kid, "base64");
  }

  if (clone.pk === "string") {
    clone.pk = encode(clone.pk);
  }

  return clone;
}

/** Normalizes a metadata object by assuring its kid is a base64 string. */
function normalizeMetadata(metadata: Metadata): Metadata {
  const clone: Metadata = { ...metadata };

  if (clone.kid && typeof clone.kid !== "string") {
    clone.kid = decode(clone.kid, "base64");
  }

  return clone;
}

/** Creates a nonce generator that is based on the current timestamp. */
function* createNonceGenerator(): Generator {
  let base: bigint = BigInt(String(Date.now()).slice(-NONCE_BYTES));

  for (;;) {
    yield encode(String(++base), "utf8");
  }
}

/** Transforms a collection of public keys to a map representation. */
function toPublicKeyMap(
  ...peerPublicKeys: PeerPublicKey[]
): Map<string, Uint8Array> {
  const map: Map<string, Uint8Array> = new Map<string, Uint8Array>();

  for (const peerPublicKey of peerPublicKeys) {
    map.set(peerPublicKey.kid as string, peerPublicKey.pk as Uint8Array);
  }

  return map;
}

/** Assembles a merges object from a metadata object and a nonce. */
function assembleMetadataAndNonce(
  metadata: Metadata,
  nonce: Uint8Array
): MetadataAndNonce {
  return { ...metadata, nonce: Array.from(nonce) };
}

/** Concatenates aad, ciphertext, and tag to a token. */
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

/** Whether given input is a valid BWT metadata object. */
function isValidMetadata(x: any): boolean {
  const now: number = Date.now();
  return (
    x &&
    SUPPORTED_BWT_VERSIONS.includes(x.typ) &&
    x.kid &&
    x.kid.length === KID_BYTES_BASE64 &&
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

/** Whether given input is a valid BWT secret key. */
function isValidSecretKey(x: Uint8Array): boolean {
  return x && x.byteLength === SECRET_KEY_BYTES;
}

/** Whether given input is a valid BWT peer public key. */
function isValidPeerPublicKey(x: PeerPublicKey): boolean {
  return (
    x && x.kid.length === KID_BYTES_BASE64 && x.pk.length === PUBLIC_KEY_BYTES
  );
}

/** Whether given input string complies to the maximum BWT token length. */
function isValidToken(x: string): boolean {
  return x && x.length <= MAX_TOKEN_LENGTH;
}

/** Efficiently derives a shared key from recurring kid strings. */
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

/** Generates a BWT key pair, optionally base64 encoded. */
export function generateKeys(outputEncoding?: string): KeyPair {
  if (outputEncoding && !BASE64_REGEX.test(outputEncoding)) {
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

/**
 * Creates a BWT stringify function.
 *
 * ownSecretKey must be a base64 encoded string or buffer of 32 bytes.
 * defaultPeerPublicKey can be a peer public key that shall be used as the 
 * default for all subsequent invocations of the returned stringify function.
 */
export function stringifier(
  ownSecretKey: string | Uint8Array,
  defaultPeerPublicKey?: PeerPublicKey
): Stringify {
  if (typeof ownSecretKey === "string") {
    ownSecretKey = encode(ownSecretKey, "base64") as Uint8Array;
  }

  if (!isValidSecretKey(ownSecretKey)) {
    return null;
  }

  if (defaultPeerPublicKey) {
    defaultPeerPublicKey = normalizePeerPublicKey(defaultPeerPublicKey);

    if (!isValidPeerPublicKey(defaultPeerPublicKey)) {
      return null;
    }
  }

  const nonceGenerator: Generator = createNonceGenerator();

  const deriveSharedKey: Function = deriveSharedKeyProto.bind(
    null,
    ownSecretKey,
    new Map<string, Uint8Array>(),
    toPublicKeyMap(defaultPeerPublicKey),
    defaultPeerPublicKey ? defaultPeerPublicKey.kid : null
  );

  /**
   * Stringifies metadata and payload to an authenticated and encrypted token.
   * 
   * metadata must be a BWT metadata object.
   * payload must be a serializable object with string keys
   * peerPublicKey must be provided if a defaultPeerPublicKey has not been 
   * passed to BWT::stringifier. It can also be used to override a default peer 
   * public key for an invocation of the stringify function.
  */
  return function stringify(
    metadata: Metadata,
    payload: Payload,
    peerPublicKey?: PeerPublicKey
  ): string {
    if (!metadata || !payload) {
      return null;
    }

    metadata = normalizeMetadata(metadata);

    if (!isValidMetadata(metadata)) {
      return null;
    }

    if (peerPublicKey) {
      peerPublicKey = normalizePeerPublicKey(peerPublicKey);

      if (!isValidPeerPublicKey(peerPublicKey)) {
        return null;
      }
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

/**
 * Creates a BWT parse function.
 * 
 * ownSecretKey must be a base64 encoded string or buffer of 32 bytes.
 * defaultPeerPublicKeys can be a peer public key collection that shall be used
 * to lookup public keys by key identifiers for all subsequent invocations of
 * the returned parse function.
 */
export function parser(
  ownSecretKey: string | Uint8Array,
  ...defaultPeerPublicKeys: PeerPublicKey[]
): Parse {
  if (typeof ownSecretKey === "string") {
    ownSecretKey = encode(ownSecretKey, "base64") as Uint8Array;
  }

  if (!isValidSecretKey(ownSecretKey)) {
    return null;
  }

  if (defaultPeerPublicKeys.length) {
    defaultPeerPublicKeys = defaultPeerPublicKeys.map(normalizePeerPublicKey);

    if (!defaultPeerPublicKeys.every(isValidPeerPublicKey)) {
      return null;
    }
  }

  const deriveSharedKey: Function = deriveSharedKeyProto.bind(
    null,
    ownSecretKey,
    new Map<string, Uint8Array>(),
    toPublicKeyMap(...defaultPeerPublicKeys),
    null
  );

  /**
   * Parses the contents of a BWT token.
   *
   * In case any part of the token is corrupt, it cannot be authenticated or 
   * encrypted, or any other unexpected state is encountered null is returned.
   *
   * token must be a BWT token.
   * peerPublicKeys must be provided if no default peer public keys have been 
   * passed to BWT::parser. This collection can also be used to override the 
   * public key lookup space for the current parse invocation.
   *
   */
  return function parse(
    token: string,
    ...peerPublicKeys: PeerPublicKey[]
  ): Contents {
    if (!isValidToken(token)) {
      return null;
    }

    if (peerPublicKeys.length) {
      peerPublicKeys = peerPublicKeys.map(normalizePeerPublicKey);

      if (!peerPublicKeys.every(isValidPeerPublicKey)) {
        return null;
      }
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
