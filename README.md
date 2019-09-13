# bwt

[![Travis](http://img.shields.io/travis/chiefbiiko/bwt.svg?style=flat)](http://travis-ci.org/chiefbiiko/bwt) [![AppVeyor](https://ci.appveyor.com/api/projects/status/github/chiefbiiko/bwt?branch=master&svg=true)](https://ci.appveyor.com/project/chiefbiiko/bwt)

**B**etter **W**eb **T**oken

*Powered by Curve25519, ChaCha20 derivatives, and Poly1305*

:warning: **Not yet formally reviewed** :construction:

## Features

- `BWT`s are [encrypted and authenticated](https://en.wikipedia.org/wiki/Authenticated_encryption) using [`XChaCha20-Poly1305`](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-01)

- stoopid simple - no [crypto agility](https://en.wikipedia.org/wiki/Crypto_agility) available to module users

- secure by design, secure by default

## What a BWT Looks Like

`QldUAAAAAWygrOCJAAABbKCs4iz5wub7BvcERzge0rd2++YzNTY2MDYzNzc5OTgx.5eHsXu2v5IUnE+DS1TVaStc=.Scb9ifOg3cEcy582KKfg7Q==`

## Usage

``` ts
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

Besides a few constants and interfaces, the module's main exports are two factory functions, `createStringify` and `createParse`, that each create corresponding marshalling functions, `stringify` and `parse`.

As `BWT` uses assymetric keys the module also exports a key generation function: `generateKeyPair`. Make sure to store your private keys somewhere safe.

In case of exceptions, fx input validation or MAC verification errors, marshalling ops return `null` rather than `throw`ing errors (to avoid leaking sensitive information). `generateKeyPair`, `createStringify`, and `createParse` will throw on invalid inputs though.

Find basic interfaces and constants below.

``` ts
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

`ownSecretKey` is the secret key of the keypair of the issuing party.

`peerPublicKey` must be the peer public key object of the party that the to-be-generated tokens are meant for.

`createStringify` mutates, zeroes the secret key buffer after computing the shared secret with the indicated peer in order to protect against attacks targeting strayman memory. Just be aware that `createStringify` clears `ownSecretKey`.

#### `createParse(ownSecretKey: Uint8Array, ...peerPublicKeys: PeerPublicKey[]): Parse`

Creates a parse function.

`ownSecretKey` is the secret key of the keypair of the party that is going to parse and verify tokens. `peerPublicKeys` must be a non-empty list of peer public key objects to be used for verification of incoming tokens.

`createParse` mutates, zeroes the secret key buffer after computing the shared secret with the indicated peer in order to protect against attacks targeting strayman memory. Just be aware that `createParse` clears `ownSecretKey`.

#### `stringify(header: Header, body: Body): string`

Stringifies a token.

`header` must contain four props:

+ `typ` set to one of the `Typ` enum variants, currently that is `Typ.BWTv0` only

+ `iat` a millisecond timestamp indicating the current time

+ `exp` a millisecond timestamp indicating the expiry of the token

+ `kid` a binary of 16 bytes, the public key identifier of the issuing party

`exp` must be greater than `iat`.

`body` must be an object. Apart from that it can contain any type of fields. Nonetheless, make sure not to bloat the body as `stringify` will return `null` if a generated token exceeds 4KiB.

In case of invalid inputs or any other exceptions `stringify` returns `null`, otherwise a `BWT` token.

#### `parse(token: string): Contents`

Parses a token.

In case of invalid inputs, exceptions, corrupt or forged tokens `parse` returns `null`, otherwise a `BWT` header and body.

Besides format and cryptographic validation `parse` verifies that the `iat` and `exp` header claims are unsigned integers, `iat <= Date.now() < exp`, and that the total token size does not exceed 4KiB.

## Dear Reviewers

**Quick setup:**

1. Install `deno`:

    `curl -fsSL https://deno.land/x/install/install.sh | sh`

2. Get this repo:

    `git clone https://github.com/chiefbiiko/bwt && cd ./bwt && mkdir ./cache`

3. Cache all dependencies and run tests:

    `DENO_DIR=./cache $HOME/.deno/bin/deno run --reload ./test.ts`

  Find all non-dev dependencies in the following two directories:

  **`./cache/deps/https/raw.githubusercontent.com/chiefbiiko/`**:
  
  [`curve25519`](https://github.com/chiefbiiko/curve25519), [`chacha20`](https://github.com/chiefbiiko/chacha20), [`hchacha20`](https://github.com/chiefbiiko/hchacha20), [`poly1305`](https://github.com/chiefbiiko/poly1305), [`chacha20-poly1305`](https://github.com/chiefbiiko/chacha20-poly1305), [`xchacha20-poly1305`](https://github.com/chiefbiiko/xchacha20-poly1305), [`std-encoding`](https://github.com/chiefbiiko/std-encoding)

  **`./cache/deps/https/deno.land/x/`**:
  
  [`base64`](https://github.com/chiefbiiko/base64)

Please open an issue for your review findings. Looking forward to your feedback!

**_Thank you for reviewing!_**

## License

[MIT](./LICENSE)
