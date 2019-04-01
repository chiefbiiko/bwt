import { test, runIfMain } from "https://deno.land/std/testing/mod.ts";
import { assertEquals } from "https://deno.land/std/testing/asserts.ts";
import { Curve25519 } from "https://denopkg.com/chiefbiiko/curve25519/mod.ts";
import {
  toUint8Array as base64ToUint8Array,
  fromUint8Array as base64FromUint8Array
} from "https://denopkg.com/chiefbiiko/base64/mod.ts";
import { Payload, Authenticator, createAuthenticator } from "./mod.ts";

function createPayload(...sources: Payload[]): Payload {
  return Object.assign({
    exp: Date.now() + 100, // required
  }, ...sources);
}

interface party {
  curve: Curve25519;
  seed: Uint8Array;
  sk: Uint8Array;
  pk: Uint8Array;
  bwt: Authenticator;
}

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
  const token: string = a.bwt.stringify(inputPayload);
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, inputPayload);
});

test(function bwtStringifyNullsIfPayloadIsNull(): void {
  assertEquals(a.bwt.stringify(null), null);
});

test(function bwtStringifyNullsIfExpiryIsNaN(): void {
  assertEquals(a.bwt.stringify(createPayload({ exp: NaN })), null);
});

test(function bwtStringifyNullsIfExpiryIsInfinity(): void {
  assertEquals(a.bwt.stringify(createPayload({ exp: Infinity })), null);
});

test(function bwtStringifyNullsIfExpiryIsNull(): void {
  assertEquals(a.bwt.stringify(createPayload({ exp: null })), null);
});

test(function bwtParseNullsIfNonceIsCorrupt(): void {
  const inputPayload: Payload = createPayload();
  let token: string = a.bwt.stringify(inputPayload);
  const rebased: Uint8Array = base64ToUint8Array(token);
  rebased[0] = 0x99;
  token = base64FromUint8Array(rebased);
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, null);
});

test(function bwtParseNullsIfTagIsCorrupt(): void {
  const inputPayload: Payload = createPayload();
  let token: string = a.bwt.stringify(inputPayload);
  const rebased: Uint8Array = base64ToUint8Array(token);
  rebased[12] = 0x99;
  token = base64FromUint8Array(rebased);
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, null);
});

test(function bwtParseNullsIfCiphertextIsCorrupt(): void {
  const inputPayload: Payload = createPayload();
  let token: string = a.bwt.stringify(inputPayload);
  const rebased: Uint8Array = base64ToUint8Array(token);
  rebased[rebased.length - 1] = 0x99;
  token = base64FromUint8Array(rebased);
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, null);
});

test(function bwtParseNullsIfExpired(): void {
  const inputPayload: Payload = createPayload({ exp: Date.now() - 1 });
  let token: string = a.bwt.stringify(inputPayload);
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, null);
});

runIfMain(import.meta, { parallel: true });
