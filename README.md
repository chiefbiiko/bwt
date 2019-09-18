# bwt

[![Travis](http://img.shields.io/travis/chiefbiiko/bwt.svg?style=flat)](http://travis-ci.org/chiefbiiko/bwt) [![AppVeyor](https://ci.appveyor.com/api/projects/status/github/chiefbiiko/bwt?branch=master&svg=true)](https://ci.appveyor.com/project/chiefbiiko/bwt)

**B**etter **W**eb **T**oken

... a web token format, generation, and verification scheme

_Powered by Curve25519, ChaCha20 derivatives, and Poly1305_

:warning: **Not yet formally reviewed** :construction:

## Features

- tokens are [encrypted and authenticated](https://en.wikipedia.org/wiki/Authenticated_encryption) using [`XChaCha20-Poly1305`](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-01)

- stoopid simple - no [crypto agility](https://en.wikipedia.org/wiki/Crypto_agility) available to module users

- secure by design, secure by default

## What a BWT Looks Like

`QldUAAAAAW0/eH7KAAABbT94gG0df5A/AEnJLyZ97kdaR7lt4TRNQ46VzlwFibS1AeZ1V/oNGmkMRiA8.ntfwswksWaG5T0SkrbJ/jiM=.3wzKeXzaleLni1dgmL8ahA==`

## Usage

```ts
import * as bwt from "https://denopkg.com/chiefbiiko/bwt/mod.ts";

const alice = { ...bwt.generateKeyPair(), stringify: null };
const bob = { ...bwt.generateKeyPair(), parse: null };

alice.stringify = bwt.createStringify(alice.secretKey, {
  kid: bob.kid,
  publicKey: bob.publicKey
});

bob.parse = bwt.createParse(bob.secretKey, {
  kid: alice.kid,
  publicKey: alice.publicKey
});

const iat = Date.now();
const exp = iat + 1000;

const token = alice.stringify(
  { typ: bwt.Typ.BWTv0, kid: alice.kid, iat, exp },
  { info: "jwt sucks" }
);

console.log("alice seals and gets this token to bob:", token);

const contents = bob.parse(token);

console.log("bob opens it...:", JSON.stringify(contents));
```

## API

### Basics

Besides a few constants and interfaces, the module's main exports are two factory functions, `createStringify -> stringify` and `createParse -> parse`.

As `BWT` uses asymmetric keys the module also exports a key generation function: `generateKeyPair`. More on [key management](#managing-keys).

Find basic interfaces and constants below.

```ts
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

/** Typ enum indicating a BWT version @ the Header.typ field. */
export const enum Typ {
  BWTv0
}

/**
 * BWT header object.
 *
 * typ must be a supported BWT version, currently that is Typ.BWTv0 only.
 * iat and exp denote the issued-at and expiry ms timestamps of a token.
 * kid is the public key identifier of the issuing peer.
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

/** BWT contents. */
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
```

### Core Callables

#### `generateKeyPair(): KeyPair`

Generates a new keypair.

#### `createStringify(ownSecretKey: Uint8Array, peerPublicKey: PeerPublicKey): Stringify`

Creates a stringify function.

`ownSecretKey` is the secret key of the issuing peer's key pair.

`peerPublicKey` must be the peer public key object of the peer that the to-be-generated tokens are meant for.

`createStringify` zeros the secret key buffer after computing the shared secret with the indicated peer. Just be aware that `createStringify` clears `ownSecretKey`.

#### `createParse(ownSecretKey: Uint8Array, ...peerPublicKeys: PeerPublicKey[]): Parse`

Creates a parse function.

`ownSecretKey` is the secret key of the keypair of the peer that is going to parse and verify tokens. `peerPublicKeys` must be a non-empty list of peer public key objects to be used for verification of incoming tokens.

`createParse` zeros the secret key buffer after deriving the shared key for the indicated peers. Just be aware that `createParse` clears `ownSecretKey`.

#### `stringify(header: Header, body: Body): string`

Stringifies a token.

`header` must contain four props:

- `typ` set to one of the `Typ` enum variants, currently that is `Typ.BWTv0` only

- `iat` a millisecond timestamp indicating the current time

- `exp` a millisecond timestamp indicating the expiry of the token, must be greater than `iat`

- `kid` a binary of 16 bytes, the public key identifier of the issuing peer

`body` must be an object. Apart from that it can contain any type of fields. Nonetheless, make sure not to bloat the body as `stringify` will return `null` if a generated token exceeds 4KiB.

In case of invalid inputs or any other exceptions `stringify` returns `null`, otherwise a `BWT` token.

#### `parse(token: string): Contents`

Parses a token.

Returns `null` if the token is malformatted, corrupt, invalid, expired, from an unknown issuer, or if any other exceptions occur while marshalling, such as `JSON.parse(body)` -> 💥

In case of a valid token `parse` returns an object containing the token `header` and `body`.

This function encapsulates all validation and cryptographic verification of a token. Note that, as `BWT` requires every token to expire, `parse` does this basic metadata check.

Additional application-specific metadata checks can be made as `parse`, besides the main body, returns the token header that contains metadata. Fx, an app could choose to reject all tokens of a certain age by additionally checking the mandatory `iat` claim of a token header.

## Managing Keys

Any peer must own a static key pair and possess its peer's public keys and key identifiers for token generation and verification. Since a shared symmetric key would allow impersonation `BWT` requires key pairs.

You can generate a key pair and the corresponding peer public key from the terminal by simply running `deno run https://deno.land/x/bwt/keygen.ts [name of key pair owner]`.

Make sure to store the key pair somewhere safe (some kind of secret store) so that the included secret key remains private.

Narrow the set of owners of a particular key pair as much as possible. Particularly, any token-issuing peer should own a key pair exclusively. Peers that only parse/verify tokens, fx a set of CRUD endpoints for a specific resource, may share a key pair.

Do renew all key pairs involved in your application setting regularly!

## Dear Reviewers

**Quick setup:**

1. Install `deno`:

   `curl -fsSL https://deno.land/x/install/install.sh | sh`

2. Get this repo:

   `git clone https://github.com/chiefbiiko/bwt && cd ./bwt && mkdir ./cache`

3. Cache all dependencies and run tests:

   `DENO_DIR=./cache $HOME/.deno/bin/deno run --reload ./test.ts`

4. Find all non-dev dependencies in the following two directories:

   **`./cache/deps/https/raw.githubusercontent.com/chiefbiiko/`**

   [`curve25519`](https://github.com/chiefbiiko/curve25519), [`chacha20`](https://github.com/chiefbiiko/chacha20), [`hchacha20`](https://github.com/chiefbiiko/hchacha20), [`poly1305`](https://github.com/chiefbiiko/poly1305), [`chacha20-poly1305`](https://github.com/chiefbiiko/chacha20-poly1305), [`xchacha20-poly1305`](https://github.com/chiefbiiko/xchacha20-poly1305), [`std-encoding`](https://github.com/chiefbiiko/std-encoding)

   **`./cache/deps/https/deno.land/x/`**

   [`base64`](https://github.com/chiefbiiko/base64)

Please open an issue for your review findings. Looking forward to your feedback!

**_Thank you for reviewing!_**

## License

[MIT](./LICENSE)
