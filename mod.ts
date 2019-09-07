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

/** Supported BWT versions. */
export const SUPPORTED_VERSIONS: Set<number> = new Set<number>([0]);

/** Maximum allowed number of characters of a token. */
export const MAX_TOKEN_CHARS: number = 4096;

/** Byte length of a Curve25519 secret key. */
export const SECRET_KEY_BYTES: number = 32;

/** Byte length of a Curve25519 public key. */
export const PUBLIC_KEY_BYTES: number = 32;

/** Byte length of a BWT kid. */
export const KID_BYTES: number = 16;

/** Byte length of a serialized header. */
const HEADER_BYTES: number = 48;

/** Global Curve25519 instance provding a scalar multiplication op. */
const CURVE25519: Curve25519 = new Curve25519();

/** BigInt byte mask. */
const BIGINT_BYTE_MASK: bigint = 255n;

/** BigInt 8. */
const BIGINT_BYTE_SHIFT: bigint = 8n;

/** "BWT" as buffer. */
const MAGIC_BWT: Uint8Array = Uint8Array.from([66, 87, 84]);

/** Typ enum indicating a BWT version @ the Header.typ field. */
export const enum Typ {
  BWTv0
}

/**
 * BWT header object.
 *
 * typ must be a supported BWT version, currently that is Typ.BWTv0 only.
 * iat and exp denote the issued-at and expiry ms timestamps of a token.
 * kid is the public key identifier of the issuing party.
 */
export interface Header {
  typ: Typ;
  iat: number;
  exp: number;
  kid: Uint8Array;
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
  (header: Header, body: Body): string;
}

/** BWT parse function. */
export interface Parse {
  (token: string): Contents;
}

/**
 * BWT keypair object including a key identifier for the public key.
 *
 * secretKey is the 32-byte secret key.
 * publicKey is the 32-byte public key.
 * kid is a 16-byte key identifier for the public key.
 */
export interface KeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  kid: Uint8Array;
}

/**
 * BWT public key of a peer.
 *
 * publicKey is the 32-byte public key.
 * kid is a 16-byte key identifer for the public key.
 * name can be an arbitrarily encoded string.
 */
export interface PeerPublicKey {
  publicKey: Uint8Array;
  kid: Uint8Array;
  name?: string;
}

/** Return values of the AEAD seal op. */
interface Sealed {
  ciphertext: Uint8Array;
  tag: Uint8Array;
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
function headerAndNonceToBuffer(header: Header, nonce: Uint8Array): Uint8Array {
  const buf: Uint8Array = new Uint8Array(HEADER_BYTES);

  buf.set(MAGIC_BWT, 0);
  buf[3] = header.typ;

  bigintToBytesBE(BigInt(header.iat), buf.subarray(4, 12));
  bigintToBytesBE(BigInt(header.exp), buf.subarray(12, 20));

  buf.set(header.kid, 20);
  buf.set(nonce, 36);

  return buf;
}

/** Converts a buffer to metadata of the form: [header, kid, nonce]. */
function bufferToMetadata(buf: Uint8Array): [Header, string, Uint8Array] {
  return [
    {
      typ: buf[3],
      iat: Number(bytesToBigIntBE(buf.subarray(4, 12))),
      exp: Number(bytesToBigIntBE(buf.subarray(12, 20))),
      kid: buf.subarray(20, 36)
    },
    decode(buf.subarray(20, 36), "base64"),
    buf.subarray(36, HEADER_BYTES)
  ];
}

/** Creates a nonce generator that is based on the current timestamp. */
function* createNonceGenerator(): Generator {
  let base: bigint = BigInt(String(Date.now()).slice(-NONCE_BYTES));

  for (;;) {
    yield encode(String(++base), "utf8");
  }
}

/** Transforms a collection of peer public keys to a shared key map. */
function toSharedKeyMap(
  ownSecretKey: Uint8Array,
  peerPublicKeys: PeerPublicKey[]
): Map<string, Uint8Array> {
  return new Map<string, Uint8Array>(
    peerPublicKeys.map(
      (peerPublicKey: PeerPublicKey): [string, Uint8Array] => [
        decode(peerPublicKey.kid, "base64"),
        CURVE25519.scalarMult(ownSecretKey, peerPublicKey.publicKey)
      ]
    )
  );
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
    x.kid.byteLength === KID_BYTES &&
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
    x.kid.byteLength === KID_BYTES &&
    x.publicKey.byteLength === PUBLIC_KEY_BYTES
  );
}

/** Whether given input string has a valid token size. */
function hasValidTokenSize(x: string): boolean {
  return x && x.length <= MAX_TOKEN_CHARS;
}

/** Generates a BWT key pair. */
export function generateKeyPair(): KeyPair {
  const seed: Uint8Array = crypto.getRandomValues(
    new Uint8Array(SECRET_KEY_BYTES)
  );

  const keypair: {
    secretKey: Uint8Array;
    publicKey: Uint8Array;
  } = CURVE25519.generateKeys(seed);

  seed.fill(0x00, 0, seed.byteLength);

  const kid: Uint8Array = crypto.getRandomValues(new Uint8Array(KID_BYTES));

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
  ownSecretKey: Uint8Array,
  peerPublicKey: PeerPublicKey
): Stringify {
  if (!isValidSecretKey(ownSecretKey)) {
    throw new TypeError("invalid secret key");
  }

  if (!isValidPeerPublicKey(peerPublicKey)) {
    throw new TypeError("invalid peer public key");
  }

  const nonceGenerator: Generator = createNonceGenerator();

  const sharedKey: Uint8Array = CURVE25519.scalarMult(
    ownSecretKey,
    peerPublicKey.publicKey
  );

  ownSecretKey.fill(0x00, 0, ownSecretKey.byteLength);

  /**
   * Stringifies header and body to an authenticated and encrypted token.
   *
   * header must be a BWT header object.
   * body must be a serializable object with string keys
   * peerPublicKey must be provided if a defaultPeerPublicKey has not been
   * passed to bwt.createStringify. It can also be used to override a default
   * peer public key for an invocation of the stringify function.
   */
  return function stringify(header: Header, body: Body): string {
    if (!isValidHeader(header) || !body) {
      return null;
    }

    let token: string;

    try {
      const nonce: Uint8Array = nonceGenerator.next().value;

      const aad: Uint8Array = headerAndNonceToBuffer(header, nonce);

      const plaintext: Uint8Array = encode(JSON.stringify(body), "utf8");

      const sealed: Sealed = seal(sharedKey, nonce, plaintext, aad);

      token = assembleToken(aad, sealed.ciphertext, sealed.tag);
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
  ownSecretKey: Uint8Array,
  ...peerPublicKeys: PeerPublicKey[]
): Parse {
  if (!isValidSecretKey(ownSecretKey)) {
    throw new TypeError("invalid secret key");
  }

  if (!peerPublicKeys.length) {
    throw new TypeError("no peer public keys provided");
  }

  if (!peerPublicKeys.every(isValidPeerPublicKey)) {
    throw new TypeError("invalid peer public keys");
  }

  const sharedKeyMap: Map<string, Uint8Array> = toSharedKeyMap(
    ownSecretKey,
    peerPublicKeys
  );

  ownSecretKey.fill(0x00, 0, ownSecretKey.byteLength);

  /**
   * Parses the contents of a BWT token.
   *
   * In case any part of the token is corrupt, it cannot be authenticated or
   * encrypted, or any other unexpected state is encountered null is returned.
   *
   * token must be a BWT token.
   * peerPublicKeys must be provided if no default peer public keys have been
   * passed to bwt.createParse. This collection can also be used to override
   * the public key lookup space for the current parse invocation.
   */
  return function parse(token: string): Contents {
    if (!hasValidTokenSize(token) || !token.startsWith("QldU")) {
      return null;
    }

    let header: Header;
    let kid: string;
    let nonce: Uint8Array;
    let body: Body;

    try {
      const parts: string[] = token.split(".");

      const aad: Uint8Array = encode(parts[0], "base64");

      [header, kid, nonce] = bufferToMetadata(aad);

      const ciphertext: Uint8Array = encode(parts[1], "base64");

      const tag: Uint8Array = encode(parts[2], "base64");

      const sharedKey: Uint8Array = sharedKeyMap.get(kid);

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
