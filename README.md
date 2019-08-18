# bwt

[![Travis](http://img.shields.io/travis/chiefbiiko/bwt.svg?style=flat)](http://travis-ci.org/chiefbiiko/bwt) [![AppVeyor](https://ci.appveyor.com/api/projects/status/github/chiefbiiko/bwt?branch=master&svg=true)](https://ci.appveyor.com/project/chiefbiiko/bwt)

**B**etter **W**eb **T**oken

> Know someone that can *security review* this module?

## What a BWT Looks Like

`QldUAAAAAWygrOCJAAABbKCs4iz5wub7BvcERzge0rd2++YzNTY2MDYzNzc5OTgx.5eHsXu2v5IUnE+DS1TVaStc=.Scb9ifOg3cEcy582KKfg7Q==`

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
  (token: string, ...peerPublicKeys: PeerPublicKey[]): Contents;
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

Generates a new keypair.

`outputEncoding` can be set to `"base64"`. By default, keys are plain `Uint8Array`s.

#### `stringifier(ownSecretKey: string | Uint8Array, defaultPeerPublicKey?: PeerPublicKey): Stringify`

Creates a stringify function.

`ownSecretKey` is the secret key of the keypair of the issuing party. Can be passed as a base64 string. `defaultPeerPublicKey` can be the peer public key object of a party that the to-be-generated tokens are meant for. If provided, it will be used as a default, i.e. when `Stringify` invocations do not receive a peer public key.

#### `parser(ownSecretKey: string | Uint8Array, ...defaultPeerPublicKeys: PeerPublicKey[]): Parse`

Creates a parse function.

`ownSecretKey` is the secret key of the keypair of the party that is going to parse and verify tokens. Can be passed as a base64 string. `defaultPeerPublicKeys` can be a series of peer public key objects that shall be used for verification of incoming tokens. If any are specified these will be used as a default, i.e. when `Parse` invocations do not receive any peer public keys to verify against.

#### `stringify(header: Header, payload: Payload, peerPublicKey?: PeerPublicKey): string`

Stringifies a token.

`header` must contain four props: 

+ `typ` set to `"BWTv0"`

+ `iat` a millisecond timestamp indicating the current time   

+ `exp` a millisecond timestamp indicating the expiry of the token

+ `kid` a base64 string or a binary of 16 bytes, the public key identifier of the issuing party

`payload` must be an object. Apart from that it can contain any type of fields.  

`peerPublicKey` can be specified to override a default peer public key and address a token to a specific party.

#### `parse(token: string, ...peerPublicKeys: PeerPublicKey[]): Contents`

Parses a token.

If `peerPublicKeys` consists of at least one peer public key, it takes precedence and any default peer public keys possibly passed when creating the parse function are ignored for verification of the `token`.

## Design

- `BWT` tokens are [encrypted and authenticated](https://en.wikipedia.org/wiki/Authenticated_encryption)
  - high-security `AEAD_CHACHA20_POLY1305` scheme
  - [RFC 8439](https://tools.ietf.org/html/rfc8439) compliant

- no [crypto agility](https://en.wikipedia.org/wiki/Crypto_agility) available to module users
  
- `BWT`s require a fixed set of four header claims: `typ`, `iat`, `exp`, `kid`

- in case of exceptions marshalling ops return `null` rather than `throw`ing errors (that possibly leak sensitive information)

## Dear Reviewers

Thank you for reviewing!

To install `deno`: `curl -fsSL https://deno.land/x/install/install.sh | sh`

Run `DENO_DIR=cache $HOME/.deno/bin/deno run ./test.ts` to run the tests and cache all dependencies into `./cache`. 
All relevant dependencies are then stored in `./cache/deps/https/raw.githubusercontent.com/chiefbiiko/` and `./cache/deps/https/deno.land/x/`.

Looking forward to your feedback! Please open an issue for your review findings. Thanks!