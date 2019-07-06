import { test, runIfMain } from "https://deno.land/std/testing/mod.ts";
import { assertEquals } from "https://deno.land/std/testing/asserts.ts";
// import * as base64 from "https://denopkg.com/chiefbiiko/base64/mod.ts";
import {
  encode,
  decode
} from "https://denopkg.com/chiefbiiko/std-encoding/mod.ts";
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

// function stringifyKid(
//   keypair: BWT.KeyPair
// ): { sk: Uint8Array; pk: Uint8Array; kid: string } {
//   return {
//     sk: keypair.sk,
//     pk: keypair.pk,
//     kid: base64.fromUint8Array(keypair.kid)
//   };
// }

interface Party {
  name: string;
  kid: string | Uint8Array;
  sk:string |  Uint8Array;
  pk:string |  Uint8Array;
  stringify?: BWT.Stringify;
  parse?: BWT.Parse;
}

const dec: TextDecoder = new TextDecoder();
const enc: TextEncoder = new TextEncoder();

const a: Party = {
  ...BWT.generateKeys(),
  stringify: null,
  name: "alice"
};

const b: Party = {
  ...BWT.generateKeys(),
  parse: null,
  name: "bob"
};

const c: Party = {
  ...BWT.generateKeys(),
  parse: null,
  name: "chiefbiiko"
};

const d: Party = {
  ...BWT.generateKeys(),
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

test({
  name: "alice and bob",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({ kid: a.kid });
    const inputPayload: BWT.Payload = createPayload();
    const token: string = a.stringify(inputMetadata, inputPayload);
    const { metadata, payload }: BWT.Contents = b.parse(token);
    assertEquals(metadata, inputMetadata);
    assertEquals(payload, inputPayload);
  }
});

test({
  name: "parse from multiple peers",
  fn(): void {
    const aliceInputMetadata: BWT.Metadata = createMetadata({ kid: a.kid });
    const chiefbiikoInputMetadata: BWT.Metadata = createMetadata({
      kid: c.kid
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
  }
});

test({
  name: "stringify with particular public key",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({ kid: c.kid });
    const inputPayload: BWT.Payload = createPayload();
    const token: string = c.stringify(inputMetadata, inputPayload, {
      kid: d.kid,
      pk: d.pk
    });
    const { metadata, payload }: BWT.Contents = d.parse(token);
    assertEquals(metadata, inputMetadata);
    assertEquals(payload, inputPayload);
  }
});

test({
  name: "parse with particular public key",
  fn(): void {
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
  }
});

test({
  name: "metadata.kid and all PeerPublicKey props can be binary or base64",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({ kid: decode(a.kid, "base64") });
    const inputPayload: BWT.Payload = createPayload();
    const token: string = a.stringify(inputMetadata, inputPayload);
    const { metadata, payload }: BWT.Contents = b.parse(token);
    assertEquals(metadata, inputMetadata);
    assertEquals(payload, inputPayload);
  }
});

test({
  name: "stringify nulls if metadata is null",
  fn(): void {
    assertEquals(a.stringify(null, createPayload()), null);
  }
});

test({
  name: "stringify nulls if payload is null",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({ kid: a.kid });
    assertEquals(a.stringify(inputMetadata, null), null);
  }
});

test({
  name: "stringify nulls if version is unsupported",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({
      typ: "BWTv419",
      kid: a.kid
    });
    assertEquals(a.stringify(inputMetadata, createPayload()), null);
  }
});

test({
  name: "parse nulls if kid is unknown",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({
      kid: "deadbeefdeadbeef"
    });
    const token: string = a.stringify(inputMetadata, createPayload());
    assertEquals(b.parse(token), null);
  }
});

test({
  name: "stringify nulls if kid is falsy",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({ kid: "" });
    assertEquals(a.stringify(inputMetadata, createPayload()), null);
  }
});

test({
  name: "stringify nulls if iat is negative",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({ iat: -1, kid: a.kid });
    assertEquals(a.stringify(inputMetadata, createPayload()), null);
  }
});

test({
  name: "stringify nulls if iat is NaN",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({
      iat: NaN,
      kid: a.kid
    });
    assertEquals(a.stringify(inputMetadata, createPayload()), null);
  }
});

test({
  name: "stringify nulls if iat is Infinity",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({
      iat: Infinity,
      kid: a.kid
    });
    assertEquals(a.stringify(inputMetadata, createPayload()), null);
  }
});

test({
  name: "stringify nulls if iat is null",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({
      iat: null,
      kid: a.kid
    });
    assertEquals(a.stringify(inputMetadata, createPayload()), null);
  }
});

test({
  name: "stringify nulls if exp is negative",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({ exp: -1, kid: a.kid });
    assertEquals(a.stringify(inputMetadata, createPayload()), null);
  }
});

test({
  name: "stringify nulls if exp is NaN",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({
      exp: NaN,
      kid: a.kid
    });
    assertEquals(a.stringify(inputMetadata, createPayload()), null);
  }
});

test({
  name: "stringify nulls if exp is Infinity",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({
      exp: Infinity,
      kid: a.kid
    });
    assertEquals(a.stringify(inputMetadata, createPayload()), null);
  }
});

test({
  name: "stringify nulls if exp is null",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({
      exp: null,
      kid: a.kid
    });
    assertEquals(a.stringify(inputMetadata, createPayload()), null);
  }
});

test({
  name: "BWT ops null if exp is due",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({
      exp: Date.now() - 1,
      kid: a.kid
    });
    assertEquals(a.stringify(inputMetadata, createPayload()), null);
  }
});

test({
  name: "parse nulls if nonce is corrupt",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({ kid: a.kid });
    const inputPayload: BWT.Payload = createPayload();
    let token: string = a.stringify(inputMetadata, inputPayload);
    const parts: string[] = token.split(".");
    const metadata: { [key: string]: number | string } = JSON.parse(
      dec.decode(encode(parts[0], "base64"))
    );
    metadata.nonce[0] ^= 0x99;
    parts[0] = decode(enc.encode(JSON.stringify(metadata)), "base64");
    token = parts.join(".");
    assertEquals(b.parse(token), null);
  }
});

test({
  name: "parse nulls if tag is corrupt",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({ kid: a.kid });
    const inputPayload: BWT.Payload = createPayload();
    let token: string = a.stringify(inputMetadata, inputPayload);
    const parts: string[] = token.split(".");
    let corruptTag: Uint8Array = encode(parts[2], "base64");
    corruptTag[0] ^= 0x99;
    parts[2] = decode(corruptTag, "base64");
    token = parts.join(".");
    assertEquals(b.parse(token), null);
  }
});

test({
  name: "parse nulls if ciphertext is corrupt",
  fn(): void {
    const inputMetadata: BWT.Metadata = createMetadata({ kid: a.kid });
    const inputPayload: BWT.Payload = createPayload();
    let token: string = a.stringify(inputMetadata, inputPayload);
    const parts: string[] = token.split(".");
    let corruptCiphertext: Uint8Array = encode(parts[1], "base64");
    corruptCiphertext[0] ^= 0x99;
    parts[1] = decode(corruptCiphertext, "base64");
    token = parts.join(".");
    assertEquals(b.parse(token), null);
  }
});

runIfMain(import.meta, { parallel: true });
