# bwt

[![Travis](http://img.shields.io/travis/chiefbiiko/bwt.svg?style=flat)](http://travis-ci.org/chiefbiiko/bwt) [![AppVeyor](https://ci.appveyor.com/api/projects/status/github/chiefbiiko/bwt?branch=master&svg=true)](https://ci.appveyor.com/project/chiefbiiko/bwt)

**B**etter **W**eb **T**oken

> Know someone that can *security review* this module?

## Features

- `BWT`s are [encrypted and authenticated](https://en.wikipedia.org/wiki/Authenticated_encryption)
  - [high-security](https://www.cryptrec.go.jp/exreport/cryptrec-ex-2601-2016.pdf) `AEAD_CHACHA20_POLY1305` scheme
  - [RFC 8439](https://tools.ietf.org/html/rfc8439) compliant

- no [crypto agility](https://en.wikipedia.org/wiki/Crypto_agility) available to module users
  
- `BWT`s require a fixed set of four header claims: `typ`, `iat`, `exp`, `kid` - no opting-out

## What a BWT Looks Like

`QldUAAAAAWygrOCJAAABbKCs4iz5wub7BvcERzge0rd2++YzNTY2MDYzNzc5OTgx.5eHsXu2v5IUnE+DS1TVaStc=.Scb9ifOg3cEcy582KKfg7Q==`

## Usage

``` ts
import * as BWT from "https://denopkg.com/chiefbiiko/bwt/mod.ts";

const alice = { ...BWT.generateKeys(), stringify: null };
const bob = { ...BWT.generateKeys(), parse: null };

alice.stringify = BWT.stringifier(alice.secretKey, {
  kid: bob.kid,
  publicKey: bob.publicKey
});

bob.parse = BWT.parser(bob.secretKey, {
  kid: alice.kid,
  publicKey: alice.publicKey
});

const iat = Date.now();
const exp = iat + 1000;

const token = alice.stringify(
  { typ: "BWTv0", kid: alice.kid, iat, exp },
  { info: "jwt sucks" }
);

const contents = bob.parse(token);

console.log("bob got this info:", contents.body.info);
```

## API

### Basics

`bwt` exports to factory functions `stringifier` and `parser` that create corresponding marshalling functions: `stringify` and `parse`.

In case of exceptions, fx input validation or MAC verification errors, marshalling ops return `null` rather than `throw`ing errors (that possibly leak sensitive information).

Find basic interfaces and constants below.

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
 * kid is a 16-byte key identifier for the public key.
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
export const SUPPORTED_VERSIONS: Set<string> = new Set<string>(["BWTv0"]);

/** Maximum allowed number of characters of a token. */
export const MAX_TOKEN_CHARS: number = 4096;

/** Byte length of a Curve25519 secret key. */
export const SECRET_KEY_BYTES: number = 32;

/** Byte length of a Curve25519 public key. */
export const PUBLIC_KEY_BYTES: number = 32;
```

### Core Callables

#### `generateKeys(outputEncoding?: string): KeyPair`

Generates a new keypair.

`outputEncoding` can be set to `"base64"`. By default, keys are plain `Uint8Array`s.

#### `stringifier(ownSecretKey: string | Uint8Array, defaultPeerPublicKey?: PeerPublicKey): Stringify`

Creates a stringify function.

`ownSecretKey` is the secret key of the keypair of the issuing party. Can be passed as a base64 string. `defaultPeerPublicKey` can be the peer public key object of a party that the to-be-generated tokens are meant for. If provided, it will be used as a default, i.e. when `Stringify` invocations do not receive a peer public key.

#### `parser(ownSecretKey: string | Uint8Array, ...defaultPeerPublicKeys: PeerPublicKey[]): Parse`

Creates a parse function.

`ownSecretKey` is the secret key of the keypair of the party that is going to parse and verify tokens. Can be passed as a base64 string. `defaultPeerPublicKeys` can be a series of peer public key objects that shall be used for verification of incoming tokens. If any are specified these will be used as a default, i.e. when `Parse` invocations do not receive any peer public keys to verify against.

#### `stringify(header: Header, body: Body, peerPublicKey?: PeerPublicKey): string`

Stringifies a token.

`header` must contain four props: 

+ `typ` set to `"BWTv0"`

+ `iat` a millisecond timestamp indicating the current time   

+ `exp` a millisecond timestamp indicating the expiry of the token

+ `kid` a base64 string or a binary of 16 bytes, the public key identifier of the issuing party

`body` must be an object. Apart from that it can contain any type of fields.  

`peerPublicKey` can be specified to override a default peer public key and address a token to a specific party.

#### `parse(token: string, ...peerPublicKeys: PeerPublicKey[]): Contents`

Parses a token.

If `peerPublicKeys` consists of at least one peer public key, it takes precedence and any default peer public keys possibly passed when creating the parse function are ignored for verification of the `token`.

## Dear Reviewers

**Quick setup:**

1. Install `deno`:

    `curl -fsSL https://deno.land/x/install/install.sh | sh`

2. Get this repo: 

    `git clone https://github.com/chiefbiiko/bwt && cd ./bwt && mkdir ./cache`

3. Cache all dependencies and run tests: 

    `DENO_DIR=./cache $HOME/.deno/bin/deno run ./test.ts`

All relevant dependencies ([`aead-chacha20-poly1305`](https://github.com/chiefbiiko/aead-chacha20-poly1305), [`curve25519`](https://github.com/chiefbiiko/curve25519), [`std-encoding`](https://github.com/chiefbiiko/std-encoding), and [`base64`](https://github.com/chiefbiiko/base64)) are then stored in `./cache/deps/https/raw.githubusercontent.com/chiefbiiko/` and `./cache/deps/https/deno.land/x/`.

Please open an issue for your review findings. Looking forward to your feedback!

**_Thank you for reviewing!_**