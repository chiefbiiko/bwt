# bwt

[![Travis](http://img.shields.io/travis/chiefbiiko/bwt.svg?style=flat)](http://travis-ci.org/chiefbiiko/bwt) [![AppVeyor](https://ci.appveyor.com/api/projects/status/github/chiefbiiko/bwt?branch=master&svg=true)](https://ci.appveyor.com/project/chiefbiiko/bwt)

**B**etter **W**eb **T**oken

> Know someone that can *security review* this module?

## Usage

``` ts
import * as BWT from "./mod.ts";

const a = BWT.generateKeys() as any;
const b = BWT.generateKeys() as any;

a.stringify = BWT.stringifier(a.sk, { name: "bob", kid: b.kid, pk: b.pk });

b.parse = BWT.parser(b.sk, { name: "alice", kid: a.kid, pk: a.pk });

const now = Date.now();
const iat = now;
const exp = now + 1000;

const token = a.stringify(
  { typ: "BWTv0", iat, exp, kid: a.kid },
  { info: "jwt sucks" }
);

const contents = b.parse(token);

console.log("bob got this info:", contents.payload.info);
```

## Design

- `BWT` tokens are [encrypted and authenticated](https://en.wikipedia.org/wiki/Authenticated_encryption)
  - high-security `AEAD_CHACHA20_POLY1305` scheme
  - [RFC 8439](https://tools.ietf.org/html/rfc8439) compliant

- no [crypto agility](https://en.wikipedia.org/wiki/Crypto_agility) available to module users
  
- `BWT`s require a fixed set of four header claims: `typ`, `iat`, `exp`, `kid`

- in case of exceptions marshalling ops return `null` rather than `throw`ing errors (that possibly leak sensitive information)

## API

### Basics

``` ts
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
export const SUPPORTED_VERSIONS: Set<string> = new Set(["BWTv0"]);

/** Maximum allowed number of characters of a token. */
export const MAX_TOKEN_CHARS: number = 4096;

/** Byte length of a Curve25519 secret key. */
export const SECRET_KEY_BYTES: number = 32;

/** Byte length of a Curve25519 public key. */
export const PUBLIC_KEY_BYTES: number = 32;
```

### Core Callables

#### `generateKeys(outputEncoding?: string): KeyPair`

Generates a new BWT keypair. `outputEncoding` can be set to `"base64"`.

...