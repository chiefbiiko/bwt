import { Curve25519 } from "https://denopkg.com/chiefbiiko/curve25519/mod.ts";
import {
  seal,
  open,
  NONCE_BYTES
} from "https://denopkg.com/chiefbiiko/aead-chacha20-poly1305/mod.ts";
import {
  encode,
  decode
} from "https://denopkg.com/chiefbiiko/std-encoding/mod.ts";

/** Typ enum indicating a BWT version. */
export const enum Typ {
  BWTv0
}

/**
 * BWT header object.
 *
 * typ must be a supported BWT version tag, currently that is "BWTv0" only.
 * iat and exp denote the issued-at and expiry ms timestamps of a token.
 * kid is the public key identifier of the issuing party. base64 encoded kid
 * strings are supported.
 */
export interface Header {
  typ: Typ;
  iat: number;
  exp: number;
  kid: string | Uint8Array;
}

/** BWT body object. */
export interface Body {
  [key: string]: unknown;
}

/** Parsed contents of a token. */
export interface Contents {
  header: Header;
  body: Body;
}

/** BWT stringify function. */
export interface Stringify {
  (header: Header, body: Body, peerPublicKey?: PeerPublicKey): string;
}

/** BWT parse function. */
export interface Parse {
  (token: string, ...peerPublicKeys: PeerPublicKey[]): Contents;
}

/**
 * BWT keypair object including a key identifier for the public key.
 *
 * secretKey is the 32-byte secret key.
 * publicKey is the 32-byte public key.
 * kid is a 16-byte key identifer for the public key.
 *
 * Any of the above properties can either be buffers or base64 strings.
 */
export interface KeyPair {
  secretKey: string | Uint8Array;
  publicKey: string | Uint8Array;
  kid: string | Uint8Array;
}

/**
 * BWT public key of a peer.
 *
 * publicKey is the 32-byte public key.
 * kid is a 16-byte key identifer for the public key.
 * name can be an arbitrarily encoded string or a buffer.
 *
 * publicKey and kid can either be buffers or base64 strings.
 */
export interface PeerPublicKey {
  publicKey: string | Uint8Array;
  kid: string | Uint8Array;
  name?: string | Uint8Array;
}

/** Supported BWT versions. */
export const SUPPORTED_VERSIONS: Set<number> = new Set<number>([0]);

/** Maximum allowed number of characters of a token. */
export const MAX_TOKEN_CHARS: number = 4096;

/** Byte length of a Curve25519 secret key. */
export const SECRET_KEY_BYTES: number = 32;

/** Byte length of a Curve25519 public key. */
export const PUBLIC_KEY_BYTES: number = 32;

/** Global Curve25519 instance provding a scalar multiplication op. */
const CURVE25519: Curve25519 = new Curve25519();

/** One-time-compiled regex for checking outputEncoding params.*/
const BASE64_REGEX: RegExp = /base64/i;

/** Char count of a 16-byte buffer in base64. */
const BASE64_KID_CHARS: number = 24;

/** Byte length of a serialized header. */
const HEADER_BYTES: number = 48;

/** BigInt byte mask. */
const BIGINT_BYTE_MASK: bigint = 255n;

/** BigInt 8. */
const BIGINT_BYTE_SHIFT: bigint = 8n;

/** "BWT" as buffer. */
const MAGIC_BWT: Uint8Array = encode("BWT", "utf8");

/** Internal object representation adding a nonce to a header object. */
interface InternalHeader extends Header {
  nonce?: Uint8Array;
  kidBuf: Uint8Array;
}

/** Bike-shed constant-time buffer equality check. */
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  let diff: number = a.length === b.length ? 0 : 1;

  for (let i: number = Math.max(a.length, b.length) - 1; i >= 0; --i) {
    diff |= a[i] ^ b[i];
  }

  return diff === 0;
}

/** Reads given bytes as an unsigned big-endian bigint. */
function bytesToBigIntBE(buf: Uint8Array): bigint {
  return buf.reduce(
    (acc: bigint, byte: number): bigint =>
      (acc << BIGINT_BYTE_SHIFT) | (BigInt(byte) & BIGINT_BYTE_MASK),
    0n
  );
}

/** Writes given timestamp to big-endian bytes of an 8-byte out buffer. */
function bigintToBytesBE(b: bigint, out: Uint8Array): void {
  for (let i: number = out.byteLength - 1; i >= 0; --i) {
    out[i] = Number(b & BIGINT_BYTE_MASK);
    b >>= BIGINT_BYTE_SHIFT;
  }
}

/** Converts a header and nonce to a buffer. */
function internalHeaderToBuffer(internalHeader: InternalHeader): Uint8Array {
  const buf: Uint8Array = new Uint8Array(HEADER_BYTES);

  buf.set(MAGIC_BWT, 0); // BWT

  //TODO

  bigintToBytesBE(BigInt(internalHeader.iat), buf.subarray(4, 12)); // iat
  bigintToBytesBE(BigInt(internalHeader.exp), buf.subarray(12, 20)); // exp

  buf.set(internalHeader.kidBuf, 20); // kid
  buf.set(internalHeader.nonce, 36); // nonce

  return buf;
}

/** Converts a buffer to a header and nonce. */
function bufferToHeaderAndNonce(buf: Uint8Array): [Header, Uint8Array] {
  const version: number = buf[3];

  if (
    !equal(buf.subarray(0, 3), MAGIC_BWT) ||
    !SUPPORTED_VERSIONS.has(version)
  ) {
    return null;
  }

  return [
    {
      typ: version,
      iat: Number(bytesToBigIntBE(buf.subarray(4, 12))),
      exp: Number(bytesToBigIntBE(buf.subarray(12, 20))),
      kid: decode(buf.subarray(20, 36), "base64")
    },
    buf.subarray(36, HEADER_BYTES)
  ];
}

/**
 * Normalizes a peer pubilc key object by assuring its kid is a base64 string
 * and ensuring that its publicKey prop is a Uint8Array.
 */
function normalizePeerPublicKey(peerPublicKey: PeerPublicKey): PeerPublicKey {
  let clone: PeerPublicKey;

  if (typeof peerPublicKey.publicKey === "string") {
    clone = {
      ...peerPublicKey,
      publicKey: encode(peerPublicKey.publicKey, "base64")
    };
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
    map.set(peerPublicKey.kid as string, peerPublicKey.publicKey as Uint8Array);
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
    SUPPORTED_VERSIONS.has(x.typ) &&
    x.kid &&
    x.kid.length === BASE64_KID_CHARS &&
    x.iat >= 0 &&
    x.iat % 1 === 0 &&
    x.iat <= now &&
    x.exp >= 0 &&
    x.exp % 1 === 0 &&
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
 * buffer publicKey prop for the byte length check.
 */
function isValidPeerPublicKey(x: PeerPublicKey): boolean {
  return (
    x &&
    x.kid &&
    x.kid.length === BASE64_KID_CHARS &&
    x.publicKey.length === PUBLIC_KEY_BYTES
  );
}

/** Whether given input string has a valid token size. */
function hasValidTokenSize(x: string): boolean {
  return x && x.length <= MAX_TOKEN_CHARS;
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

    publicKey = peerPublicKey ? (peerPublicKey.publicKey as Uint8Array) : null;
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
export function generateKeyPair(outputEncoding?: string): KeyPair {
  if (outputEncoding && !BASE64_REGEX.test(outputEncoding)) {
    throw new TypeError('outputEncoding must be undefined or "base64"');
  }

  const keypair: {
    secretKey: Uint8Array;
    publicKey: Uint8Array;
  } = CURVE25519.generateKeys(crypto.getRandomValues(new Uint8Array(32)));

  const kid: Uint8Array = crypto.getRandomValues(new Uint8Array(16));

  if (outputEncoding) {
    return {
      secretKey: decode(keypair.secretKey, "base64"),
      publicKey: decode(keypair.publicKey, "base64"),
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
export function createStringify(
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
   * Stringifies header and body to an authenticated and encrypted token.
   *
   * header must be a BWT header object.
   * body must be a serializable object with string keys
   * peerPublicKey must be provided if a defaultPeerPublicKey has not been
   * passed to BWT::createStringify. It can also be used to override a default
   * peer public key for an invocation of the stringify function.
   */
  return function stringify(
    header: Header,
    body: Body,
    peerPublicKey?: PeerPublicKey
  ): string {
    if (!header || !body) {
      return null;
    }

    const internalHeader: InternalHeader = normalizeHeader(header);

    if (!isValidHeader(internalHeader)) {
      return null;
    }

    if (peerPublicKey) {
      peerPublicKey = normalizePeerPublicKey(peerPublicKey);

      if (!isValidPeerPublicKey(peerPublicKey)) {
        return null;
      }
    }

    let token: string;

    try {
      const sharedKey: Uint8Array = deriveSharedKey.apply(
        null,
        peerPublicKey ? [peerPublicKey.kid, peerPublicKey] : []
      );

      const nonce: Uint8Array = nonceGenerator.next().value;

      internalHeader.nonce = nonce;

      const aad: Uint8Array = internalHeaderToBuffer(internalHeader);

      const plaintext: Uint8Array = encode(JSON.stringify(body), "utf8");

      const {
        ciphertext,
        tag
      }: { ciphertext: Uint8Array; tag: Uint8Array } = seal(
        sharedKey,
        nonce,
        plaintext,
        aad
      );

      token = assembleToken(aad, ciphertext, tag);
    } catch (_) {
      return null;
    }

    if (!hasValidTokenSize(token)) {
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
export function createParse(
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
   * passed to BWT::createParse. This collection can also be used to override
   * the public key lookup space for the current parse invocation.
   */
  return function parse(
    token: string,
    ...peerPublicKeys: PeerPublicKey[]
  ): Contents {
    if (!hasValidTokenSize(token)) {
      return null;
    }

    if (peerPublicKeys.length) {
      peerPublicKeys = peerPublicKeys.map(normalizePeerPublicKey);

      if (!peerPublicKeys.every(isValidPeerPublicKey)) {
        return null;
      }
    }

    let header: Header;
    let nonce: Uint8Array;
    let body: Body;

    try {
      const parts: string[] = token.split(".");

      const aad: Uint8Array = encode(parts[0], "base64");

      const ciphertext: Uint8Array = encode(parts[1], "base64");

      const tag: Uint8Array = encode(parts[2], "base64");

      [header, nonce] = bufferToHeaderAndNonce(aad);

      const sharedKey: Uint8Array = deriveSharedKey(
        header.kid,
        ...peerPublicKeys
      );

      const plaintext: Uint8Array = open(
        sharedKey,
        nonce,
        ciphertext,
        aad,
        tag
      );

      body = JSON.parse(decode(plaintext, "utf8"));
    } catch (_) {
      return null;
    }

    if (!body || !isValidHeader(header)) {
      return null;
    }

    return { header, body };
  };
}
