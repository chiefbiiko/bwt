import { test, runIfMain } from "https://deno.land/std/testing/mod.ts";
import { assertEquals } from "https://deno.land/std/testing/asserts.ts";
import * as base64 from "https://denopkg.com/chiefbiiko/base64/mod.ts";
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

function stringifyKid(
  keypair: BWT.KeyPair
): { sk: Uint8Array; pk: Uint8Array; kid: string } {
  return {
    sk: keypair.sk,
    pk: keypair.pk,
    kid: base64.fromUint8Array(keypair.kid)
  };
}

interface Party {
  name: string;
  kid: string;
  sk: Uint8Array;
  pk: Uint8Array;
  stringify?: BWT.Stringify;
  parse?: BWT.Parse;
}

const dec: TextDecoder = new TextDecoder();
const enc: TextEncoder = new TextEncoder();

const a: Party = {
  ...stringifyKid(BWT.generateKeys()),
  stringify: null,
  name: "alice"
};
const b: Party = {
  ...stringifyKid(BWT.generateKeys()),
  parse: null,
  name: "bob"
};
const c: Party = {
  ...stringifyKid(BWT.generateKeys()),
  parse: null,
  name: "chiefbiiko"
};
const d: Party = {
  ...stringifyKid(BWT.generateKeys()),
  parse: null,
  name: "djb"
};

// creating their workhorses
a.stringify = BWT.stringifier(a.sk, { name: "bob", kid: b.kid, pk: b.pk });

b.parse = BWT.parser(
  b.sk,
  {
    name: a.name,
    kid: a.kid,
    pk: a.pk
  },
  {
    name: c.name,
    kid: c.kid,
    pk: c.pk
  }
);

c.stringify = BWT.stringifier(c.sk, {
  name: b.name,
  kid: b.kid,
  pk: b.pk
});

d.parse = BWT.parser(d.sk, {
  name: c.name,
  kid: c.kid,
  pk: c.pk
});

test(function bwtAliceAndBob(): void {
  const inputMetadata: BWT.Metadata = createMetadata({ kid: a.kid });
  const inputPayload: BWT.Payload = createPayload();
  const token: string = a.stringify(inputMetadata, inputPayload);
  const { metadata, payload }: BWT.Contents = b.parse(token);
  assertEquals(metadata, inputMetadata);
  assertEquals(payload, inputPayload);
});

test(function bwtParseFromMultipleIssuers(): void {
  const aliceInputMetadata: BWT.Metadata = createMetadata({ kid: a.kid });
  const chiefbiikoInputMetadata: BWT.Metadata = createMetadata({ kid: c.kid });
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
  const inputMetadata: BWT.Metadata = createMetadata({ kid: c.kid });
  const inputPayload: BWT.Payload = createPayload();
  const token: string = c.stringify(inputMetadata, inputPayload, {
    kid: d.kid,
    pk: d.pk
  });
  const { metadata, payload }: BWT.Contents = d.parse(token);
  assertEquals(metadata, inputMetadata);
  assertEquals(payload, inputPayload);
});

test(function bwtParseWithParticularPublicKey(): void {
  const inputMetadata: BWT.Metadata = createMetadata({ kid: a.kid });
  const inputPayload: BWT.Payload = createPayload();
  const token: string = a.stringify(inputMetadata, inputPayload, {
    kid: d.kid,
    pk: d.pk
  });
  const { metadata, payload }: BWT.Contents = d.parse(token, {
    kid: a.kid,
    pk: a.pk
  });
  assertEquals(metadata, inputMetadata);
  assertEquals(payload, inputPayload);
});

test(function bwtStringifyNullsIfMetadataIsNull(): void {
  assertEquals(a.stringify(null, createPayload()), null);
});

test(function bwtStringifyNullsIfPayloadIsNull(): void {
  const inputMetadata: BWT.Metadata = createMetadata({ kid: a.kid });
  assertEquals(a.stringify(inputMetadata, null), null);
});

test(function bwtStringifyNullsIfVersionIsUnsupported(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    typ: "BWTv419",
    kid: a.kid
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtParseNullsIfKeyIdentifierIsUnknown(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    kid: "deadbeefdeadbeef"
  });
  const token: string = a.stringify(inputMetadata, createPayload());
  assertEquals(b.parse(token), null);
});

test(function bwtStringifyNullsIfKeyIdentifierIsFalsy(): void {
  const inputMetadata: BWT.Metadata = createMetadata({ kid: "" });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfIssuedAtIsNegative(): void {
  const inputMetadata: BWT.Metadata = createMetadata({ iat: -1, kid: a.kid });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfIssuedAtIsNaN(): void {
  const inputMetadata: BWT.Metadata = createMetadata({ iat: NaN, kid: a.kid });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfIssuedAtIsInfinity(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    iat: Infinity,
    kid: a.kid
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfIssuedAtIsNull(): void {
  const inputMetadata: BWT.Metadata = createMetadata({ iat: null, kid: a.kid });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfExpiryIsNegative(): void {
  const inputMetadata: BWT.Metadata = createMetadata({ exp: -1, kid: a.kid });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfExpiryIsNaN(): void {
  const inputMetadata: BWT.Metadata = createMetadata({ exp: NaN, kid: a.kid });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfExpiryIsInfinity(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    exp: Infinity,
    kid: a.kid
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtStringifyNullsIfExpiryIsNull(): void {
  const inputMetadata: BWT.Metadata = createMetadata({ exp: null, kid: a.kid });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtOperationsNullIfExpiryIsDue(): void {
  const inputMetadata: BWT.Metadata = createMetadata({
    exp: Date.now() - 1,
    kid: a.kid
  });
  assertEquals(a.stringify(inputMetadata, createPayload()), null);
});

test(function bwtParseNullsIfNonceIsCorrupt(): void {
  const inputMetadata: BWT.Metadata = createMetadata({ kid: a.kid });
  const inputPayload: BWT.Payload = createPayload();
  let token: string = a.stringify(inputMetadata, inputPayload);
  const parts: string[] = token.split(".");
  const metadata: { [key: string]: number | string } = JSON.parse(
    dec.decode(base64.toUint8Array(parts[0]))
  );
  metadata.nonce[0] ^= 0x99;
  parts[0] = base64.fromUint8Array(enc.encode(JSON.stringify(metadata)));
  token = parts.join(".");
  assertEquals(b.parse(token), null);
});

test(function bwtParseNullsIfTagIsCorrupt(): void {
  const inputMetadata: BWT.Metadata = createMetadata({ kid: a.kid });
  const inputPayload: BWT.Payload = createPayload();
  let token: string = a.stringify(inputMetadata, inputPayload);
  const parts: string[] = token.split(".");
  let corruptTag: Uint8Array = base64.toUint8Array(parts[2]);
  corruptTag[0] ^= 0x99;
  parts[2] = base64.fromUint8Array(corruptTag);
  token = parts.join(".");
  assertEquals(b.parse(token), null);
});

test(function bwtParseNullsIfCiphertextIsCorrupt(): void {
  const inputMetadata: BWT.Metadata = createMetadata({ kid: a.kid });
  const inputPayload: BWT.Payload = createPayload();
  let token: string = a.stringify(inputMetadata, inputPayload);
  const parts: string[] = token.split(".");
  let corruptCiphertext: Uint8Array = base64.toUint8Array(parts[1]);
  corruptCiphertext[0] ^= 0x99;
  parts[1] = base64.fromUint8Array(corruptCiphertext);
  token = parts.join(".");
  assertEquals(b.parse(token), null);
});

runIfMain(import.meta, { parallel: true });
