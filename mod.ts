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
 * BWT header object.
 *
 * typ must be a supported BWT version tag, currently that is "BWTv0" only.
 * iat and exp denote the issued-at and expiry ms timestamps of a token.
 * kid is the public key identifier of the issuing party. base64 encoded kid
 * strings are supported.
 */
export interface Header {
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
  header: Header;
  payload: Payload;
}

/** BWT stringify function. */
export interface Stringify {
  (header: Header, payload: Payload, peerPublicKey?: PeerPublicKey): string;
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

/** Maximum allowed number of characters of a token. */
export const MAX_BWT_SIZE: number = 4096;

/** Byte length of a Curve25519 secret key. */
export const SECRET_KEY_BYTES: number = 32;

/** Byte length of a Curve25519 public key. */
export const PUBLIC_KEY_BYTES: number = 32;

/** Internal object representation adding a nonce to a header object. */
interface InternalHeader extends Header {
  nonce?: Uint8Array;
  kidBuf: Uint8Array;
}

/** Global Curve25519 instance provding a scalar multiplication op. */
const CURVE25519: Curve25519 = new Curve25519();

/** One-time-compiled regex for checking outputEncoding params.*/
const BASE64_REGEX: RegExp = /base64/i;

/** Char count of a 16-byte buffer in base64. */
const KID_BASE64_CHARS: number = 24;

/** "BWT" as buffer. */
const BWT_BUF: Uint8Array = encode("BWT", "utf8");

/** Byte length of a serialized header. */
const HEADER_BUFFER_BYTES: number = 48;

/** Converts a header and nonce to a buffer. */
function internalHeaderToBuffer(internalHeader: InternalHeader): Uint8Array {
  const buf: Uint8Array = new Uint8Array(HEADER_BUFFER_BYTES);
  const dataView: DataView = new DataView(buf.buffer);

  buf.set(BWT_BUF, 0); // "BWT"
  buf[3] = parseInt(internalHeader.typ[3], 10); // version

  dataView.setBigUint64(4, BigInt(internalHeader.iat), false); // iat
  dataView.setBigUint64(12, BigInt(internalHeader.exp), false); // exp

  buf.set(internalHeader.kidBuf, 20); // kid
  buf.set(internalHeader.nonce, 36); // nonce

  return buf;
}

/** Converts a buffer to a header and nonce. */
function bufferToInternalHeader(buf: Uint8Array): InternalHeader {
  const dataView: DataView = new DataView(buf.buffer);

  const internalHeader: InternalHeader = {} as InternalHeader;

  internalHeader.typ = decode(buf.subarray(0, 3), "utf8") + "v" + buf[3];

  internalHeader.iat = Number(dataView.getBigUint64(4, false));
  internalHeader.exp = Number(dataView.getBigUint64(12, false));

  internalHeader.kid = decode(buf.subarray(20, 36), "base64");
  internalHeader.nonce = buf.subarray(36, HEADER_BUFFER_BYTES);

  return internalHeader;
}

/**
 * Normalizes a peer pubilc key object by assuring its kid is a base64 string
 * and ensuring that its pk prop is a Uint8Array.
 */
function normalizePeerPublicKey(peerPublicKey: PeerPublicKey): PeerPublicKey {
  let clone: PeerPublicKey;

  if (typeof peerPublicKey.pk === "string") {
    clone = { ...peerPublicKey, pk: encode(peerPublicKey.pk, "base64") };
  }

  if (typeof peerPublicKey.kid !== "string") {
    if (!clone) {
      clone = { ...peerPublicKey, kid: decode(peerPublicKey.kid, "base64") };
    } else {
      clone.kid = decode(peerPublicKey.kid, "base64");
    }
  }

  return clone || peerPublicKey;
}

/** Normalizes a header object by assuring its kid is a base64 string. */
function normalizeHeader(header: Header): InternalHeader {
  if (header.kid instanceof Uint8Array) {
    return { ...header, kidBuf: header.kid, kid: decode(header.kid, "base64") };
  } else if (typeof header.kid === "string") {
    return { ...header, kidBuf: encode(header.kid, "base64"), kid: header.kid };
  }
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

/** Whether given input is a valid BWT header object. */
function isValidHeader(x: any): boolean {
  const now: number = Date.now();
  return (
    x &&
    SUPPORTED_BWT_VERSIONS.includes(x.typ) &&
    x.kid &&
    x.kid.length === KID_BASE64_CHARS &&
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

/**
 *  Whether given input is a valid BWT peer public key.
 *
 * This function must be passed normalized peer public keys as it assumes a
 * buffer pk prop for the byte length check.
 */
function isValidPeerPublicKey(x: PeerPublicKey): boolean {
  return (
    x &&
    x.kid &&
    x.kid.length === KID_BASE64_CHARS &&
    x.pk.length === PUBLIC_KEY_BYTES
  );
}

/** Whether given input string complies to the maximum BWT token length. */
function hasValidTokenLength(x: string): boolean {
  return x && x.length <= MAX_BWT_SIZE;
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
export function generateKeys(outputEncoding: string = "base64"): KeyPair {
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
   * Stringifies header and payload to an authenticated and encrypted token.
   *
   * header must be a BWT header object.
   * payload must be a serializable object with string keys
   * peerPublicKey must be provided if a defaultPeerPublicKey has not been
   * passed to BWT::stringifier. It can also be used to override a default peer
   * public key for an invocation of the stringify function.
   */
  return function stringify(
    header: Header,
    payload: Payload,
    peerPublicKey?: PeerPublicKey
  ): string {
    if (!header || !payload) {
      return null;
    }

    let internalHeader: InternalHeader = normalizeHeader(header);

    if (!isValidHeader(internalHeader)) {
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
      internalHeader.nonce = nonce;
      aad = internalHeaderToBuffer(internalHeader);
      plaintext = encode(JSON.stringify(payload), "utf8");
      sealed = seal(sharedKey, nonce, plaintext, aad);
      token = assembleToken(aad, sealed.ciphertext, sealed.tag);
    } catch (_) {
      return null;
    }

    if (!hasValidTokenLength(token)) {
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
    if (!hasValidTokenLength(token)) {
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
    let internalHeader: InternalHeader;
    let ciphertext: Uint8Array;
    let tag: Uint8Array;
    let plaintext: Uint8Array;
    let payload: Payload;

    try {
      parts = token.split(".");
      aad = encode(parts[0], "base64");
      ciphertext = encode(parts[1], "base64");
      tag = encode(parts[2], "base64");
      internalHeader = bufferToInternalHeader(aad);
      sharedKey = deriveSharedKey(internalHeader.kid, ...peerPublicKeys);
      plaintext = open(sharedKey, internalHeader.nonce, ciphertext, aad, tag);
      payload = JSON.parse(decode(plaintext, "utf8"));
    } catch (_) {
      return null;
    }

    if (!payload || !isValidHeader(internalHeader)) {
      return null;
    }

    delete internalHeader.nonce;

    return { header: internalHeader as Header, payload };
  };
}
