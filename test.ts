import { test, runIfMain } from "https://deno.land/std/testing/mod.ts";
import { assertEquals } from "https://deno.land/std/testing/asserts.ts";
import { Curve25519 } from "./../curve25519/mod.ts";
import {
  Payload,
  Authenticator,
  Curve25519Keys,
  createAuthenticator
} from "./mod.ts";

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

test(function bwtAliceStringifiesBobParsesSuccesfully(): void {
  const inputPayload: Payload = { fraud: "money", expires: Date.now() + 100 };
  const token: string = a.bwt.stringify(inputPayload);
  console.error('token', token)
  const outputPayload: Payload = b.bwt.parse(token);
  assertEquals(outputPayload.fraud, inputPayload.fraud);
});

runIfMain(import.meta);
