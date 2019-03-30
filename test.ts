import { test, runIfMain } from "https://deno.land/std/testing/mod.ts";
import { assertEquals } from "https://deno.land/std/testing/asserts.ts";
import { Curve25519 } from "./../curve25519/mod.ts";
import { Payload, Authenticator, createAuthenticator } from "./mod.ts";
import { toByteArray, fromByteArray } from "./util.ts";

function createPayload(...sources): Payload {
  return Object.assign(
    { fraud: "money", expires: Date.now() + 100 },
    ...sources
  );
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
  assertEquals(outputPayload.fraud, inputPayload.fraud);
  assertEquals(outputPayload.expires, inputPayload.expires);
});

test(function bwtParsesNullOnCorruptNonce(): void {
  const inputPayload: Payload = createPayload();
  let token: string = a.bwt.stringify(inputPayload);
  const rebased: Uint8Array = toByteArray(token);
  rebased[0] = 0x99;
  token = fromByteArray(rebased);
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, null);
});

test(function bwtParsesNullOnCorruptTag(): void {
  const inputPayload: Payload = createPayload();
  let token: string = a.bwt.stringify(inputPayload);
  const rebased: Uint8Array = toByteArray(token);
  rebased[12] = 0x99;
  token = fromByteArray(rebased);
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, null);
});

test(function bwtParsesNullOnCorruptCiphertext(): void {
  const inputPayload: Payload = createPayload();
  let token: string = a.bwt.stringify(inputPayload);
  const rebased: Uint8Array = toByteArray(token);
  rebased[rebased.length - 1] = 0x99;
  token = fromByteArray(rebased);
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, null);
});

test(function bwtParsesNullIfExpired(): void {
  const inputPayload: Payload = createPayload({ expires: Date.now() - 1 });
  let token: string = a.bwt.stringify(inputPayload);
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload, null);
});

runIfMain(import.meta, { parallel: true });
