import { test, runIfMain } from "https://deno.land/std/testing/mod.ts";
import { assertEquals } from "https://deno.land/std/testing/asserts.ts";
import { Curve25519 } from "https://denopkg.com/chiefbiiko/curve25519/mod.ts";
import {
  toUint8Array as base64ToUint8Array,
  fromUint8Array as base64FromUint8Array
} from "https://denopkg.com/chiefbiiko/base64/mod.ts";
import { Metadata, Payload, Authenticator, createAuthenticator } from "./mod.ts";

function createMetadata(...sources: Object[]): Metadata {
  return Object.assign({
    typ: "BWT1",
    iss: "chiefbiiko",
    aud: "nobody",
    kid: "chiefbiiko_public_key",
    iat: Date.now(),
    exp: Date.now() + 100
  }, ...sources);
}

function createPayload(...sources: Payload[]): Payload {
  return Object.assign({ fraud: "fraud" }, ...sources);
}

interface party {
  curve: Curve25519;
  seed: Uint8Array;
  sk: Uint8Array;
  pk: Uint8Array;
  bwt: Authenticator;
}

const dec: TextDecoder = new TextDecoder();
const enc: TextEncoder = new TextEncoder();

// alice
const a: party = {
  curve: new Curve25519(),
  seed: new TextEncoder().encode("deadbeefdeadbeefdeadbeefdeadbeef"),
  sk: null,
  pk: null,
  bwt: null
};

// bob
const b: party = {
  curve: new Curve25519(),
  seed: a.seed.map((byte: number): number => byte - 36),
  sk: null,
  pk: null,
  bwt: null
};

// generating their keypairs
Object.assign(a, a.curve.generateKeys(a.seed));
Object.assign(b, b.curve.generateKeys(b.seed));

// creating their authenticators
a.bwt = createAuthenticator({
  ownSecretKey: a.sk,
  peerPublicKey: b.pk
});

b.bwt = createAuthenticator({
  ownSecretKey: b.sk,
  peerPublicKey: a.pk
});

test(function bwtAliceAndBob(): void {
  const inputPayload: Payload = createPayload();
  const token: string = a.bwt.stringify(createMetadata(), inputPayload);
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, inputPayload);
});

test(function bwtStringifyNullsIfPayloadIsNull(): void {
  assertEquals(a.bwt.stringify(createMetadata(), null), null);
});

test(function bwtStringifyNullsIfExpiryIsNaN(): void {
  assertEquals(a.bwt.stringify(createMetadata({ exp: NaN }), createPayload()), null);
});

test(function bwtStringifyNullsIfExpiryIsInfinity(): void {
  assertEquals(a.bwt.stringify(createMetadata({ exp: Infinity }), createPayload()), null);
});

test(function bwtStringifyNullsIfExpiryIsNull(): void {
  assertEquals(a.bwt.stringify(createMetadata({ exp: null }), createPayload()), null);
});

test(function bwtParseNullsIfNonceIsCorrupt(): void {
  const inputPayload: Payload = createPayload();
  let token: string = a.bwt.stringify(createMetadata(), inputPayload);
  const parts: string[] = token.split('.')
  const metadata: { [key: string]: number | string } = JSON.parse(dec.decode(base64ToUint8Array(parts[0])))
  metadata.nonce[0] = 0x99;
  parts[0] = base64FromUint8Array(enc.encode(JSON.stringify(metadata)))
  token = parts.join('.')
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, null);
});

test(function bwtParseNullsIfTagIsCorrupt(): void {
  const inputPayload: Payload = createPayload();
  let token: string = a.bwt.stringify(createMetadata(), inputPayload);
  const parts: string[] = token.split('.')
  let corruptTag: Uint8Array = base64ToUint8Array(parts[2])
  corruptTag[0] = 0x99;
  parts[2] = base64FromUint8Array(corruptTag)
  token = parts.join('.')
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, null);
});

test(function bwtParseNullsIfCiphertextIsCorrupt(): void {
  const inputPayload: Payload = createPayload();
  let token: string = a.bwt.stringify(createMetadata(), inputPayload);
  const parts: string[] = token.split('.')
  let corruptCiphertext: Uint8Array = base64ToUint8Array(parts[1])
  corruptCiphertext[0] = 0x99;
  parts[1] = base64FromUint8Array(corruptCiphertext)
  token = parts.join('.')
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, null);
});

test(function bwtParseNullsIfExpired(): void {
  let token: string = a.bwt.stringify(createMetadata({ exp: Date.now() - 1 }), createPayload());
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, null);
});

runIfMain(import.meta, { parallel: true });
