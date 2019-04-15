import { test, runIfMain } from "https://deno.land/std/testing/mod.ts";
import { assertEquals } from "https://deno.land/std/testing/asserts.ts";
import { Curve25519 } from "https://denopkg.com/chiefbiiko/curve25519/mod.ts";
import {
  toUint8Array as base64ToUint8Array,
  fromUint8Array as base64FromUint8Array
} from "https://denopkg.com/chiefbiiko/base64/mod.ts";
import * as BWT from "./mod.ts";

function createMetadata(...sources: Object[]): BWT.Metadata {
  return Object.assign(
    {
      typ: "BWTv1",
      iss: "alice",
      aud: "bob",
      kid: "alice_public_key",
      iat: Date.now(),
      exp: Date.now() + 100
    },
    ...sources
  );
}

function createPayload(...sources: BWT.Payload[]): BWT.Payload {
  return Object.assign({ fraud: "fraud" }, ...sources);
}

interface party {
  curve: Curve25519;
  seed: Uint8Array;
  sk: Uint8Array;
  pk: Uint8Array;
  stringify?: BWT.Stringify;
  parse?: BWT.Parse;
}

const dec: TextDecoder = new TextDecoder();
const enc: TextEncoder = new TextEncoder();

// alice aka the auth endpoint
const a: party = {
  curve: new Curve25519(),
  seed: new TextEncoder().encode("deadbeefdeadbeefdeadbeefdeadbeef"),
  sk: null,
  pk: null,
  stringify: null
};

// bob aka a resource endpoint
const b: party = {
  curve: new Curve25519(),
  seed: a.seed.map((byte: number): number => byte - 36),
  sk: null,
  pk: null,
  parse: null
};

// generating their keypairs
Object.assign(a, a.curve.generateKeys(a.seed));
Object.assign(b, b.curve.generateKeys(b.seed));

// creating their authenticators
a.stringify = BWT.stringifier(a.sk, {
  kid: "bob_public_key",
  publicKey: b.pk
});

b.parse = BWT.parser("bob", b.sk, {
  kid: "alice_public_key",
  publicKey: a.pk
});

test(function bwtAliceAndBob(): void {
  const inputMetadata: BWT.Metadata = createMetadata();
  const inputPayload: BWT.Payload = createPayload();
  const token: string = a.stringify(inputMetadata, inputPayload);
  const { metadata, payload }: BWT.Payload = b.parse(token);
  assertEquals(metadata, inputMetadata);
  assertEquals(payload, inputPayload);
});

test(function bwtStringifyWithParticularPublicKey(): void {
  // resetting alice's stringify to actually have a different public key cached
  a.stringify = BWT.stringifier(a.sk, {
    kid: "bert_public_key",
    publicKey: new Uint8Array(32)
  });
  const inputMetadata: BWT.Metadata = createMetadata();
  const inputPayload: BWT.Payload = createPayload();
  const token: string = a.stringify(inputMetadata, inputPayload, {
    kid: "bob_public_key",
    publicKey: b.pk
  });
  const { metadata, payload }: BWT.Payload = b.parse(token);
  assertEquals(metadata, inputMetadata);
  assertEquals(payload, inputPayload);
});

test(function bwtParseWithParticularPublicKey(): void {
  // resetting bob's parse to actually have a different public key cached
  b.parse = BWT.parser("bob", b.sk, {
    kid: "anita_public_key",
    publicKey: new Uint8Array(32)
  });
  const inputMetadata: BWT.Metadata = createMetadata();
  const inputPayload: BWT.Payload = createPayload();
  const token: string = a.stringify(inputMetadata, inputPayload);
  const { metadata, payload }: BWT.Payload = b.parse(token, {
    kid: "alice_public_key",
    publicKey: a.pk
  });
  assertEquals(metadata, inputMetadata);
  assertEquals(payload, inputPayload);
});

test(function bwtParseNullsIfKidIsUnknown(): void {
  const metadata: BWT.Metadata = createMetadata({
    kid: "anita_public_key",
    publicKey: a.pk
  });
  const token: string = a.stringify(metadata, createPayload());
  const parsed = b.parse(token);
  assertEquals(parsed, null);
});

test(function bwtParseNullsIfAudIsUnknown(): void {
  const token: string = a.stringify(
    createMetadata({ aud: "anonymous" }),
    createPayload()
  );
  const parsed = b.parse(token);
  assertEquals(parsed, null);
});

test(function bwtStringifyNullsIfMetadataIsNull(): void {
  assertEquals(a.stringify(null, createPayload()), null);
});

test(function bwtStringifyNullsIfPayloadIsNull(): void {
  assertEquals(a.stringify(createMetadata(), null), null);
});

test(function bwtStringifyNullsIfExpiryIsNaN(): void {
  assertEquals(
    a.stringify(createMetadata({ exp: NaN }), createPayload()),
    null
  );
});

test(function bwtStringifyNullsIfExpiryIsInfinity(): void {
  assertEquals(
    a.stringify(createMetadata({ exp: Infinity }), createPayload()),
    null
  );
});

test(function bwtStringifyNullsIfExpiryIsNull(): void {
  assertEquals(
    a.stringify(createMetadata({ exp: null }), createPayload()),
    null
  );
});

test(function bwtParseNullsIfNonceIsCorrupt(): void {
  const inputPayload: BWT.Payload = createPayload();
  let token: string = a.stringify(createMetadata(), inputPayload);
  const parts: string[] = token.split(".");
  const metadata: { [key: string]: number | string } = JSON.parse(
    dec.decode(base64ToUint8Array(parts[0]))
  );
  metadata.nonce[0] = 0x99;
  parts[0] = base64FromUint8Array(enc.encode(JSON.stringify(metadata)));
  token = parts.join(".");
  assertEquals(b.parse(token), null);
});

test(function bwtParseNullsIfTagIsCorrupt(): void {
  const inputPayload: BWT.Payload = createPayload();
  let token: string = a.stringify(createMetadata(), inputPayload);
  const parts: string[] = token.split(".");
  let corruptTag: Uint8Array = base64ToUint8Array(parts[2]);
  corruptTag[0] = 0x99;
  parts[2] = base64FromUint8Array(corruptTag);
  token = parts.join(".");
  assertEquals(b.parse(token), null);
});

test(function bwtParseNullsIfCiphertextIsCorrupt(): void {
  const inputPayload: BWT.Payload = createPayload();
  let token: string = a.stringify(createMetadata(), inputPayload);
  const parts: string[] = token.split(".");
  let corruptCiphertext: Uint8Array = base64ToUint8Array(parts[1]);
  corruptCiphertext[0] = 0x99;
  parts[1] = base64FromUint8Array(corruptCiphertext);
  token = parts.join(".");
  assertEquals(b.parse(token), null);
});

test(function bwtParseNullsIfExpired(): void {
  let token: string = a.stringify(
    createMetadata({ exp: Date.now() - 1 }),
    createPayload()
  );
  assertEquals(b.parse(token), null);
});

runIfMain(import.meta, { parallel: true });
