import { test, runIfMain } from "https://deno.land/std/testing/mod.ts";

import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

import {
  encode,
  decode
} from "https://denopkg.com/chiefbiiko/std-encoding/mod.ts";

import * as BWT from "./mod.ts";

function createHeader(
  source: { [key: string]: number | Uint8Array | string } = {}
): BWT.Header {
  // Normalize kids to strings as parse returns a base64 string header.kid.
  // Doing this for assertEqual reasons.
  // bwt actually allows base64 strings or buffers as inputs for binary stuff.
  if (source.kid instanceof Uint8Array) {
    source.kid = decode(source.kid, "base64");
  }

  return {
    typ: "BWTv0",
    kid: "",
    iat: Date.now(),
    exp: Date.now() + 419,
    ...source
  };
}

function createPayload(...sources: BWT.Payload[]): BWT.Payload {
  return { fraud: "fraud", ...sources };
}

interface Party {
  name: string;
  kid: string | Uint8Array;
  sk: string | Uint8Array;
  pk: string | Uint8Array;
  stringify?: BWT.Stringify;
  parse?: BWT.Parse;
}

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
    const inputHeader: BWT.Header = createHeader({ kid: a.kid });
    const inputPayload: BWT.Payload = createPayload();

    const token: string = a.stringify(inputHeader, inputPayload);

    const { header, payload }: BWT.Contents = b.parse(token);

    assertEquals(header, inputHeader);
    assertEquals(payload, inputPayload);
  }
});

test({
  name: "parse from multiple peers",
  fn(): void {
    const aliceInputHeader: BWT.Header = createHeader({ kid: a.kid });

    const chiefbiikoInputHeader: BWT.Header = createHeader({
      kid: c.kid
    });

    const inputPayload: BWT.Payload = createPayload();

    const aliceToken: string = a.stringify(aliceInputHeader, inputPayload);

    const chiefbiikoToken: string = c.stringify(
      chiefbiikoInputHeader,
      inputPayload
    );

    const fromAlice: BWT.Contents = b.parse(aliceToken);

    const fromChiefbiiko: BWT.Contents = b.parse(chiefbiikoToken);

    assertEquals(fromAlice.header, aliceInputHeader);
    assertEquals(fromAlice.payload, inputPayload);
    assertEquals(fromChiefbiiko.header, chiefbiikoInputHeader);
    assertEquals(fromChiefbiiko.payload, inputPayload);
  }
});

test({
  name: "stringify with particular public key",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({ kid: c.kid });
    const inputPayload: BWT.Payload = createPayload();

    const token: string = c.stringify(inputHeader, inputPayload, {
      kid: d.kid,
      pk: d.pk
    });

    const { header, payload }: BWT.Contents = d.parse(token);

    assertEquals(header, inputHeader);
    assertEquals(payload, inputPayload);
  }
});

test({
  name: "parse with particular public key",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({ kid: a.kid });
    const inputPayload: BWT.Payload = createPayload();

    const token: string = a.stringify(inputHeader, inputPayload, {
      kid: d.kid,
      pk: d.pk
    });

    const { header, payload }: BWT.Contents = d.parse(token, {
      kid: a.kid,
      pk: a.pk
    });

    assertEquals(header, inputHeader);
    assertEquals(payload, inputPayload);
  }
});

test({
  name: "header.kid and all PeerPublicKey props can be binary or base64",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({
      kid: decode(a.kid as Uint8Array, "base64")
    });
    const inputPayload: BWT.Payload = createPayload();

    const token: string = a.stringify(inputHeader, inputPayload);

    const { header, payload }: BWT.Contents = b.parse(token);

    assertEquals(header, inputHeader);
    assertEquals(payload, inputPayload);
  }
});

test({
  name: "stringify nulls if header is null",
  fn(): void {
    assertEquals(a.stringify(null, createPayload()), null);
  }
});

test({
  name: "stringify nulls if payload is null",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({ kid: a.kid });

    assertEquals(a.stringify(inputHeader, null), null);
  }
});

test({
  name: "stringify nulls if version is unsupported",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({
      typ: "BWTv419",
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createPayload()), null);
  }
});

test({
  name: "parse nulls if kid is unknown",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({
      kid: "deadbeefdeadbeef"
    });

    const token: string = a.stringify(inputHeader, createPayload());

    assertEquals(b.parse(token), null);
  }
});

test({
  name: "stringify nulls if kid is falsy",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({ kid: "" });

    assertEquals(a.stringify(inputHeader, createPayload()), null);
  }
});

test({
  name: "stringify nulls if iat is negative",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({ iat: -1, kid: a.kid });

    assertEquals(a.stringify(inputHeader, createPayload()), null);
  }
});

test({
  name: "stringify nulls if iat is NaN",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({
      iat: NaN,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createPayload()), null);
  }
});

test({
  name: "stringify nulls if iat is Infinity",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({
      iat: Infinity,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createPayload()), null);
  }
});

test({
  name: "stringify nulls if iat is null",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({
      iat: null,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createPayload()), null);
  }
});

test({
  name: "stringify nulls if exp is negative",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({ exp: -1, kid: a.kid });

    assertEquals(a.stringify(inputHeader, createPayload()), null);
  }
});

test({
  name: "stringify nulls if exp is NaN",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({
      exp: NaN,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createPayload()), null);
  }
});

test({
  name: "stringify nulls if exp is Infinity",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({
      exp: Infinity,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createPayload()), null);
  }
});

test({
  name: "stringify nulls if exp is null",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({
      exp: null,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createPayload()), null);
  }
});

test({
  name: "BWT ops null if exp is due",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({
      exp: Date.now() - 1,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createPayload()), null);
  }
});

test({
  name: "parse nulls if aad is corrupt",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({ kid: a.kid });
    const inputPayload: BWT.Payload = createPayload();

    let token: string = a.stringify(inputHeader, inputPayload);

    const parts: string[] = token.split(".");

    // const header: { [key: string]: number | string } = JSON.parse(
    //   decode(encode(parts[0], "base64"), "utf8")
    // );
    // 
    // header.nonce[0] ^= 0x99;
    // 
    // parts[0] = decode(encode(JSON.stringify(header), "utf8"), "base64");
    const headerBuf: Uint8Array = encode(parts[0], "base64");
    
    headerBuf[36] ^= 0x99;

    parts[0] = decode(headerBuf, "base64");

    token = parts.join(".");

    assertEquals(b.parse(token), null);
  }
});

test({
  name: "parse nulls if nonce is corrupt",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({ kid: a.kid });
    const inputPayload: BWT.Payload = createPayload();

    let token: string = a.stringify(inputHeader, inputPayload);

    const parts: string[] = token.split(".");

    // const header: { [key: string]: number | string } = JSON.parse(
    //   decode(encode(parts[0], "base64"), "utf8")
    // );
    // 
    // header.nonce[0] ^= 0x99;
    // 
    // parts[0] = decode(encode(JSON.stringify(header), "utf8"), "base64");
    const headerBuf: Uint8Array = encode(parts[0], "base64");
    
    headerBuf[headerBuf.byteLength - 1] ^= 0x99;

    parts[0] = decode(headerBuf, "base64");

    token = parts.join(".");

    assertEquals(b.parse(token), null);
  }
});

test({
  name: "parse nulls if tag is corrupt",
  fn(): void {
    const inputHeader: BWT.Header = createHeader({ kid: a.kid });
    const inputPayload: BWT.Payload = createPayload();

    let token: string = a.stringify(inputHeader, inputPayload);

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
    const inputHeader: BWT.Header = createHeader({ kid: a.kid });
    const inputPayload: BWT.Payload = createPayload();

    let token: string = a.stringify(inputHeader, inputPayload);

    const parts: string[] = token.split(".");

    let corruptCiphertext: Uint8Array = encode(parts[1], "base64");

    corruptCiphertext[0] ^= 0x99;

    parts[1] = decode(corruptCiphertext, "base64");

    token = parts.join(".");

    assertEquals(b.parse(token), null);
  }
});

runIfMain(import.meta, { parallel: true, });
