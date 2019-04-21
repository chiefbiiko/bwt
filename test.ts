import { test, runIfMain } from "https://deno.land/std/testing/mod.ts";
import { assertEquals } from "https://deno.land/std/testing/asserts.ts";
import { Curve25519 } from "https://denopkg.com/chiefbiiko/curve25519/mod.ts";
import {
  toUint8Array,
  fromUint8Array
} from "https://denopkg.com/chiefbiiko/base64/mod.ts";
import * as BWT from "./mod.ts";

function createMetadata(...sources: Object[]): BWT.Metadata {
  return Object.assign(
    {
      typ: "BWTv0",
      kid: "",
      iat: Date.now(),
      exp: Date.now() + 419
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

// alice is an auth endpoint
const a: party = {
  curve: new Curve25519(),
  seed: enc.encode("deadbeefdeadbeefdeadbeefdeadbeef"),
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

// chiefbiiko is an auth endpoint
const c: party = {
  curve: new Curve25519(),
  seed: a.seed.map((byte: number): number => byte - 44),
  sk: null,
  pk: null,
  parse: null
};

// djb is a resource endpoint
const d: party = {
  curve: new Curve25519(),
  seed: a.seed.map((byte: number): number => byte - 32),
  sk: null,
  pk: null,
  parse: null
};

// generating their keypairs
Object.assign(a, a.curve.generateKeys(a.seed));
Object.assign(b, b.curve.generateKeys(b.seed));
Object.assign(c, c.curve.generateKeys(c.seed));
Object.assign(d, d.curve.generateKeys(d.seed));

// creating their workhorses
a.stringify = BWT.stringifier(a.sk, {
  kid: "bob_public_key",
  publicKey: b.pk
});

b.parse = BWT.parser(
  b.sk,
  {
    kid: "alice_public_key",
    publicKey: a.pk
  },
  {
    kid: "chiefbiiko_public_key",
    publicKey: c.pk
  }
);

c.stringify = BWT.stringifier(c.sk, {
  kid: "bob_public_key",
  publicKey: b.pk
});

d.parse = BWT.parser(d.sk, {
  kid: "chiefbiiko_public_key",
  publicKey: c.pk
});

test(function bwtAliceAndBob(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    kid: "alice_public_key"
  });
  const inputPayload: BWT.Payload = createPayload();
  const token: string = a.stringify(inputMetadata, inputPayload);
  const { metadata, payload }: BWT.Contents = b.parse(token);
  assertEquals(metadata, inputMetadata);
  assertEquals(payload, inputPayload);
});

test(function bwtParseFromMultipleIssuers(): void {
  const aliceInputMetadata: BWT.Metadata = createMetadata({
    kid: "alice_public_key"
  });
  const chiefbiikoInputMetadata: BWT.Metadata = createMetadata({
    kid: "chiefbiiko_public_key"
  });
  const inputPayload: BWT.Payload = createPayload();
  const aliceToken: string = a.stringify(aliceInputMetadata, inputPayload);
  const chiefbiikoToken: string = c.stringify(
    chiefbiikoInputMetadata,
    inputPayload
  );
  const fromAlice: BWT.Contents = b.parse(aliceToken);
  const fromChiefbiiko: BWT.Contents = b.parse(chiefbiikoToken);
  assertEquals(fromAlice.metadata, aliceInputMetadata);
  assertEquals(fromAlice.payload, inputPayload);
  assertEquals(fromChiefbiiko.metadata, chiefbiikoInputMetadata);
  assertEquals(fromChiefbiiko.payload, inputPayload);
});

test(function bwtStringifyWithParticularPublicKey(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    kid: "chiefbiiko_public_key"
  });
  const inputPayload: BWT.Payload = createPayload();
  const token: string = c.stringify(inputMetadata, inputPayload, {
    kid: "djb_public_key",
    publicKey: d.pk
  });
  const { metadata, payload }: BWT.Contents = d.parse(token);
  assertEquals(metadata, inputMetadata);
  assertEquals(payload, inputPayload);
});

test(function bwtParseWithParticularPublicKey(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    kid: "alice_public_key"
  });
  const inputPayload: BWT.Payload = createPayload();
  const token: string = a.stringify(inputMetadata, inputPayload, {
    kid: "djb_public_key",
    publicKey: d.pk
  });
  const { metadata, payload }: BWT.Contents = d.parse(token, {
    kid: "alice_public_key",
    publicKey: a.pk
  });
  assertEquals(metadata, inputMetadata);
  assertEquals(payload, inputPayload);
});

test(function bwtStringifyNullsIfMetadataIsNull(): void {
  assertEquals(a.stringify(null, createPayload()), null);
});

test(function bwtStringifyNullsIfPayloadIsNull(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    kid: "alice_public_key"
  });
  assertEquals(a.stringify(inputMetadata, null), null);
});

test(function bwtStringifyNullsIfVersionIsUnsupported(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    typ: "BWTv419",
    kid: "alice_public_key"
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtParseNullsIfKeyIdentifierIsUnknown(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    kid: "anita_public_key"
  });
  const token: string = a.stringify(inputMetadata, createPayload());
  assertEquals(b.parse(token), null);
});

test(function bwtStringifyNullsIfKeyIdentifierIsFalsy(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    kid: ""
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfIssuedAtIsNegative(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    iat: -1,
    kid: "alice_public_key"
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfIssuedAtIsNaN(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    iat: NaN,
    kid: "alice_public_key"
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfIssuedAtIsInfinity(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    iat: Infinity,
    kid: "alice_public_key"
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfIssuedAtIsNull(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    iat: null,
    kid: "alice_public_key"
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfExpiryIsNegative(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    exp: -1,
    kid: "alice_public_key"
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfExpiryIsNaN(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    exp: NaN,
    kid: "alice_public_key"
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfExpiryIsInfinity(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    exp: Infinity,
    kid: "alice_public_key"
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfExpiryIsNull(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    exp: null,
    kid: "alice_public_key"
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtOperationsNullIfExpiryIsDue(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    exp: Date.now() - 1,
    kid: "alice_public_key"
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtParseNullsIfNonceIsCorrupt(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    kid: "alice_public_key"
  });
  const inputPayload: BWT.Payload = createPayload();
  let token: string = a.stringify(inputMetadata, inputPayload);
  const parts: string[] = token.split(".");
  const metadata: { [key: string]: number | string } = JSON.parse(
    dec.decode(toUint8Array(parts[0]))
  );
  metadata.nonce[0] ^= 0x99;
  parts[0] = fromUint8Array(enc.encode(JSON.stringify(metadata)));
  token = parts.join(".");
  assertEquals(b.parse(token), null);
});

test(function bwtParseNullsIfTagIsCorrupt(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    kid: "alice_public_key"
  });
  const inputPayload: BWT.Payload = createPayload();
  let token: string = a.stringify(inputMetadata, inputPayload);
  const parts: string[] = token.split(".");
  let corruptTag: Uint8Array = toUint8Array(parts[2]);
  corruptTag[0] ^= 0x99;
  parts[2] = fromUint8Array(corruptTag);
  token = parts.join(".");
  assertEquals(b.parse(token), null);
});

test(function bwtParseNullsIfCiphertextIsCorrupt(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    kid: "alice_public_key"
  });
  const inputPayload: BWT.Payload = createPayload();
  let token: string = a.stringify(inputMetadata, inputPayload);
  const parts: string[] = token.split(".");
  let corruptCiphertext: Uint8Array = toUint8Array(parts[1]);
  corruptCiphertext[0] ^= 0x99;
  parts[1] = fromUint8Array(corruptCiphertext);
  token = parts.join(".");
  assertEquals(b.parse(token), null);
});

runIfMain(import.meta, { parallel: true });
