import {
  Curve25519,
  encode,
  decode,
  hchacha20,
  HCHACHA20_OUTPUT_BYTES,
  HCHACHA20_NONCE_BYTES,
  seal,
  open,
  XCHACHA20_POLY1305_NONCE_BYTES,
  XCHACHA20_POLY1305_AAD_BYTES_MAX,
  XCHACHA20_POLY1305_PLAINTEXT_BYTES_MAX,
  XCHACHA20_CIPHERTEXT_BYTES_MAX
} from "./deps.ts";

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
const HEADER_BYTES: number = 60;

/** Global Curve25519 instance provding a scalar multiplication op. */
const CURVE25519: Curve25519 = new Curve25519();

/** BigInt byte mask. */
const BIGINT_BYTE_MASK: bigint = 255n;

/** BigInt 8. */
const BIGINT_BYTE_SHIFT: bigint = 8n;

/** "BWT" as buffer - magic bytes. */
const BWT_MAGIC: Uint8Array = Uint8Array.from([66, 87, 84]);

/** HChacha20 all-zero nonce used for key stretching. */
const HCHACHA20_ZERO_NONCE: Uint8Array = new Uint8Array(HCHACHA20_NONCE_BYTES);

/** BWT context constant used with HChaCha20 for key stretching. */
const BWT_CONTEXT: Uint8Array = encode("BETTER_WEB_TOKEN", "utf8");

/** BWT format regex. */
const BWT_PATTERN: RegExp =
  /^QldU[A-Za-z0-9-_=]{76}\.[A-Za-z0-9-_=]{4,3990}\.[A-Za-z0-9-_=]{24}$/;

/** Curve25519 low-order public keys. https://cr.yp.to/ecdh.html#validate */
const LOW_ORDER_PUBLIC_KEYS: Uint8Array[] = [
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "4Ot6fDtBuK4WVuP68Z_EatoJjeucMrH9hmIFFl9JuAA=",
  "X5yVvKNQjCSx0LFVnIPvWwREXMRYHI6G2CJO3dCfEVc=",
  "7P_______________________________________38=",
  "7f_______________________________________38=",
  "7v_______________________________________38=",
  "zet6fDtBuK4WVuP68Z_EatoJjeucMrH9hmIFFl9JuIA=",
  "TJyVvKNQjCSx0LFVnIPvWwREXMRYHI6G2CJO3dCfEdc=",
  "2f________________________________________8=",
  "2v________________________________________8=",
  "2_________________________________________8="
].map((publicKey: string): Uint8Array => encode(publicKey, "base64"));

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
  (header: Header, body: Body): null | string;
}

/** BWT parse function. */
export interface Parse {
  (token: string): null | Contents;
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

/** Return values of the xchacha20-poly1305 seal op. */
interface Sealed {
  aad: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

/** Branchless buffer equality check. */
function constantTimeEqual(
  actual: Uint8Array,
  expected: Uint8Array,
  length: number
): boolean {
  let diff: number = 0;

  for (let i: number = 0; i < length; ++i) {
    diff |= actual[i] ^ expected[i];
  }

  return diff === 0;
}

/** Whether given public key has a low order? */
function isLowOrderPublicKey(publicKey: Uint8Array): boolean {
  return LOW_ORDER_PUBLIC_KEYS.some(lowOrderPublicKey =>
    constantTimeEqual(publicKey, lowOrderPublicKey, PUBLIC_KEY_BYTES)
  );
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

/** Converts a header and nonce to a 60-byte buffer. */
function headerAndNonceToBuffer(
  header: Header,
  nonce: Uint8Array
): Uint8Array {
  const buf: Uint8Array = new Uint8Array(HEADER_BYTES);

  buf.set(BWT_MAGIC, 0);
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

/** Shared key derivation. */
function deriveSharedKey(
  secretKey: Uint8Array,
  publicKey: Uint8Array
): Uint8Array {
  const sharedSecret: Uint8Array = CURVE25519.scalarMult(secretKey, publicKey);

  const sharedKey: Uint8Array = new Uint8Array(HCHACHA20_OUTPUT_BYTES);

  hchacha20(sharedKey, sharedSecret, HCHACHA20_ZERO_NONCE, BWT_CONTEXT);

  sharedSecret.fill(0x00);

  return sharedKey;
}

/** Transforms a collection of peer public keys to a shared key map. */
function toSharedKeyMap(
  ownSecretKey: Uint8Array,
  peerPublicKeys: PeerPublicKey[]
): Map<string, Uint8Array> {
  return new Map<string, Uint8Array>(
    peerPublicKeys.map((peerPublicKey: PeerPublicKey): [string, Uint8Array] =>
      [
        decode(peerPublicKey.kid, "base64"),
        deriveSharedKey(ownSecretKey, peerPublicKey.publicKey)
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

/** Whether given input is a valid BWT peer public key. */
function isValidPeerPublicKey(x: PeerPublicKey): boolean {
  return (
    x &&
    x.kid &&
    x.kid.byteLength === KID_BYTES &&
    x.publicKey &&
    x.publicKey.byteLength === PUBLIC_KEY_BYTES &&
    !isLowOrderPublicKey(x.publicKey)
  );
}

/** Whether given input string has a valid token size. */
function hasValidTokenSize(x: string): boolean {
  return x.length <= MAX_TOKEN_CHARS;
}

/** Naive BWT format validation. */
function hasValidTokenFormat(x: string): boolean {
  return BWT_PATTERN.test(x);
}

/** Generates a BWT key pair. */
export function generateKeyPair(): KeyPair {
  const seed: Uint8Array = new Uint8Array(SECRET_KEY_BYTES);
  const kid: Uint8Array = new Uint8Array(KID_BYTES);

  crypto.getRandomValues(seed);

  // keypair is null only if seed.length != 32 :: SECRET_KEY_BYTES === 32
  const keypair: {
    secretKey: Uint8Array;
    publicKey: Uint8Array;
  } = CURVE25519.generateKeys(seed) as {
    secretKey: Uint8Array;
    publicKey: Uint8Array;
  };

  seed.fill(0x00);

  if (isLowOrderPublicKey(keypair.publicKey)) {
    keypair.secretKey.fill(0x00);

    return generateKeyPair();
  }

  crypto.getRandomValues(kid);

  return { ...keypair, kid };
}

/**
 * Creates a BWT stringify function.
 *
 * ownSecretKey must be a buffer of 32 bytes.
 * peerPublicKey must be a peer public key object.
 *
 * Throws TypeErrors if any of its arguments are invalid.
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

  const sharedKey: Uint8Array = deriveSharedKey(
    ownSecretKey,
    peerPublicKey.publicKey
  );

  /**
   * Stringifies header and body to an authenticated and encrypted token.
   *
   * header must be a BWT header object.
   * body must be a serializable object with string keys.
   *
   * Returns null in case of invalid inputs, if the body is too big
   * (token.length > 4096), or other exceptions, fx JSON.stringify(body) -> 💥
   */
  return function stringify(header: Header, body: Body): null | string {
    if (!isValidHeader(header) || !body) {
      return null;
    }

    let token: string;

    try {
      const nonce: Uint8Array = crypto.getRandomValues(
        new Uint8Array(XCHACHA20_POLY1305_NONCE_BYTES)
      );

      const aad: Uint8Array = headerAndNonceToBuffer(header, nonce);

      if (aad.byteLength > XCHACHA20_POLY1305_AAD_BYTES_MAX) {
        return null;
      }

      const plaintext: Uint8Array = encode(JSON.stringify(body), "utf8");

      if (plaintext.byteLength > XCHACHA20_POLY1305_PLAINTEXT_BYTES_MAX) {
        return null;
      }

      // NOTE: all args to seal r of correct length - will return Sealed
      const sealed: Sealed = seal(sharedKey, nonce, plaintext, aad) as Sealed;

      plaintext.fill(0x00);

      token = assembleToken(sealed.aad, sealed.ciphertext, sealed.tag);
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
 * ownSecretKey must be a buffer of 32 bytes.
 * peerPublicKeys must be a non-empty peer public key collection to be used for
 * verification of incoming tokens.
 *
 * Throws TypeErrors if any of its arguments are invalid.
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

  /**
   * Parses the contents of a BWT token.
   *
   * token must be a BWT token.
   *
   * Returns null if the token is malformatted, corrupt, expired, from an
   * unknown issuer, or if any other exceptions occur while marshalling, such as
   * JSON.parse(body) -> 💥
   *
   * In case of a valid token parse returns an object containing the token
   * header and body.
   *
   * This function encapsulates all validation and cryptographic verification of
   * a token. Note that, as BWT requires every token to expire, parse does this
   * basic metadata check.
   *
   * Additional application-specific metadata checks can be made as parse,
   * besides the main body, returns the token header that contains metadata. Fx,
   * an app could choose to reject all tokens of a certain age by additionally
   * checking the mandatory iat claim of a token header.
   */
  return function parse(token: string): null | Contents {
    if (!hasValidTokenFormat(token)) {
      return null;
    }

    let header: Header;
    let body: Body;

    try {
      let kid: string;
      let nonce: Uint8Array;

      const parts: string[] = token.split(".");

      const aad: Uint8Array = encode(parts[0], "base64");

      if (aad.byteLength > XCHACHA20_POLY1305_AAD_BYTES_MAX) {
        return null;
      }

      [header, kid, nonce] = bufferToMetadata(aad);

      const ciphertext: Uint8Array = encode(parts[1], "base64");

      if (ciphertext.byteLength > XCHACHA20_CIPHERTEXT_BYTES_MAX) {
        return null;
      }

      const tag: Uint8Array = encode(parts[2], "base64");

      const sharedKey: undefined | Uint8Array = sharedKeyMap.get(kid);

      if (!sharedKey) {
        return null;
      }

      const plaintext: null | Uint8Array = open(
        sharedKey,
        nonce,
        ciphertext,
        aad,
        tag
      );

      if (!plaintext) {
        return null;
      }

      const jsonPlaintext: string = decode(plaintext, "utf8");

      plaintext.fill(0x00);

      body = JSON.parse(jsonPlaintext);
    } catch (_) {
      return null;
    }

    if (!body || body.constructor !== Object || !isValidHeader(header)) {
      return null;
    }

    return { header, body };
  };
}
