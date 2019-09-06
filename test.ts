import { test, runIfMain } from "https://deno.land/std/testing/mod.ts";
import {
  assertEquals,
  assertThrows
} from "https://deno.land/std/testing/asserts.ts";
import {
  encode,
  decode
} from "https://denopkg.com/chiefbiiko/std-encoding/mod.ts";

import * as bwt from "./mod.ts";

function createHeader(
  source: { [key: string]: number | Uint8Array | string } = {}
): bwt.Header {
  const kid: string =
    source.kid instanceof Uint8Array
      ? decode(source.kid, "base64")
      : (source.kid as string);
  return {
    typ: bwt.Typ.BWTv0,
    iat: Date.now(),
    exp: Date.now() + 419,
    ...source,
    kid
  };
}

function createBody(...sources: bwt.Body[]): bwt.Body {
  return { fraud: "fraud", ...sources };
}

interface Party {
  name: string;
  kid: string | Uint8Array;
  secretKey: string | Uint8Array;
  publicKey: string | Uint8Array;
  stringify?: bwt.Stringify;
  parse?: bwt.Parse;
}

const a: Party = { ...bwt.generateKeyPair(), stringify: null, name: "alice" };
const b: Party = { ...bwt.generateKeyPair(), parse: null, name: "bob" };
const c: Party = {
  ...bwt.generateKeyPair(),
  stringify: null,
  name: "chiefbiiko"
};
const d: Party = { ...bwt.generateKeyPair(), parse: null, name: "djb" };

a.stringify = bwt.createStringify(a.secretKey, {
  name: "bob",
  kid: b.kid,
  publicKey: b.publicKey
});

b.parse = bwt.createParse(
  b.secretKey,
  {
    name: a.name,
    kid: a.kid,
    publicKey: a.publicKey
  },
  {
    name: c.name,
    kid: c.kid,
    publicKey: c.publicKey
  }
);

c.stringify = bwt.createStringify(c.secretKey, {
  name: b.name,
  kid: b.kid,
  publicKey: b.publicKey
});

d.parse = bwt.createParse(d.secretKey, {
  name: c.name,
  kid: c.kid,
  publicKey: c.publicKey
});

test({
  name: "alice and bob",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ kid: a.kid });
    const inputBody: bwt.Body = createBody();

    const token: string = a.stringify(inputHeader, inputBody);

    const { header, body }: bwt.Contents = b.parse(token);

    assertEquals(header, inputHeader);
    assertEquals(body, inputBody);
  }
});

test({
  name: "parse from multiple peers",
  fn(): void {
    const aliceInputHeader: bwt.Header = createHeader({ kid: a.kid });

    const chiefbiikoInputHeader: bwt.Header = createHeader({
      kid: c.kid
    });

    const inputBody: bwt.Body = createBody();

    const aliceToken: string = a.stringify(aliceInputHeader, inputBody);

    const chiefbiikoToken: string = c.stringify(
      chiefbiikoInputHeader,
      inputBody
    );

    const fromAlice: bwt.Contents = b.parse(aliceToken);

    const fromChiefbiiko: bwt.Contents = b.parse(chiefbiikoToken);

    assertEquals(fromAlice.header, aliceInputHeader);
    assertEquals(fromAlice.body, inputBody);
    assertEquals(fromChiefbiiko.header, chiefbiikoInputHeader);
    assertEquals(fromChiefbiiko.body, inputBody);
  }
});

test({
  name: "stringify with particular public key",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ kid: c.kid });
    const inputBody: bwt.Body = createBody();

    const token: string = c.stringify(inputHeader, inputBody, {
      kid: d.kid,
      publicKey: d.publicKey
    });

    const { header, body }: bwt.Contents = d.parse(token);

    assertEquals(header, inputHeader);
    assertEquals(body, inputBody);
  }
});

test({
  name: "parse with particular public key",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ kid: a.kid });
    const inputBody: bwt.Body = createBody();

    const token: string = a.stringify(inputHeader, inputBody, {
      kid: d.kid,
      publicKey: d.publicKey
    });

    const { header, body }: bwt.Contents = d.parse(token, {
      kid: a.kid,
      publicKey: a.publicKey
    });

    assertEquals(header, inputHeader);
    assertEquals(body, inputBody);
  }
});

test({
  name: "keys can can be binary and/or base64",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ kid: a.kid });
    const inputBody: bwt.Body = createBody();

    const token: string = a.stringify(inputHeader, inputBody);

    const { header, body }: bwt.Contents = b.parse(token, {
      publicKey: decode(a.publicKey as Uint8Array, "base64"),
      kid: a.kid
    });

    assertEquals(header, inputHeader);
    assertEquals(body, inputBody);
  }
});

test({
  name: "generateKeyPair throws if outputEncoding is invalid",
  fn(): void {
    assertThrows((): void => {
      bwt.generateKeyPair("base44");
    }, TypeError);
  }
});

test({
  name: "createStringify throws if ownSecretKey is an invalid base64 string",
  fn(): void {
    assertThrows((): void => {
      bwt.createStringify("Qldu");
    }, TypeError);
  }
});

test({
  name: "createStringify throws if ownSecretKey is an invalid buffer",
  fn(): void {
    assertThrows((): void => {
      bwt.createStringify(Uint8Array.from([1, 2, 3]));
    }, TypeError);
  }
});

test({
  name: "createStringify throws if defaultPeerPublicKey.publicKey is invalid",
  fn(): void {
    assertThrows((): void => {
      bwt.createStringify(new Uint8Array(bwt.SECRET_KEY_BYTES), {
        publicKey: new Uint8Array(bwt.PUBLIC_KEY_BYTES - 1),
        kid: new Uint8Array(bwt.KID_BYTES)
      });
    }, TypeError);
  }
});

test({
  name: "createStringify throws if defaultPeerPublicKe.kid is invalid",
  fn(): void {
    assertThrows((): void => {
      bwt.createStringify(new Uint8Array(bwt.SECRET_KEY_BYTES), {
        publicKey: new Uint8Array(bwt.PUBLIC_KEY_BYTES),
        kid: new Uint8Array(bwt.KID_BYTES - 1)
      });
    }, TypeError);
  }
});

test({
  name: "createParse throws if ownSecretKey is an invalid base64 string",
  fn(): void {
    assertThrows((): void => {
      bwt.createParse("Qldu");
    }, TypeError);
  }
});

test({
  name: "createParse throws if ownSecretKey is an invalid buffer",
  fn(): void {
    assertThrows((): void => {
      bwt.createParse(Uint8Array.from([1, 2, 3]));
    }, TypeError);
  }
});

test({
  name: "createParse throws if defaultPeerPublicKey.publicKey is invalid",
  fn(): void {
    assertThrows((): void => {
      bwt.createParse(new Uint8Array(bwt.SECRET_KEY_BYTES), {
        publicKey: new Uint8Array(bwt.PUBLIC_KEY_BYTES - 1),
        kid: new Uint8Array(bwt.KID_BYTES)
      });
    }, TypeError);
  }
});

test({
  name: "createParse throws if defaultPeerPublicKey.kid is invalid",
  fn(): void {
    assertThrows((): void => {
      bwt.createParse(new Uint8Array(bwt.SECRET_KEY_BYTES), {
        publicKey: new Uint8Array(bwt.PUBLIC_KEY_BYTES),
        kid: new Uint8Array(bwt.KID_BYTES - 1)
      });
    }, TypeError);
  }
});

test({
  name: "stringify nulls if header is null",
  fn(): void {
    assertEquals(a.stringify(null, createBody()), null);
  }
});

test({
  name: "stringify nulls if body is null",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ kid: a.kid });

    assertEquals(a.stringify(inputHeader, null), null);
  }
});

test({
  name: "stringify nulls if version is unsupported",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({
      typ: 419,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "parse nulls if kid is unknown",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({
      kid: "deadbeefdeadbeef"
    });

    const token: string = a.stringify(inputHeader, createBody());

    assertEquals(b.parse(token), null);
  }
});

test({
  name: "stringify nulls if kid is falsy",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ kid: "" });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if iat is negative",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ iat: -1, kid: a.kid });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if iat is NaN",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({
      iat: NaN,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if iat is Infinity",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({
      iat: Infinity,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if iat is null",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({
      iat: null,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if exp is negative",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ exp: -1, kid: a.kid });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if exp is NaN",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({
      exp: NaN,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if exp is Infinity",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({
      exp: Infinity,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if exp is null",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({
      exp: null,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "BWT ops null if exp is due",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({
      exp: Date.now() - 1,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "parse nulls if aad is corrupt",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ kid: a.kid });
    const inputBody: bwt.Body = createBody();

    let token: string = a.stringify(inputHeader, inputBody);

    const parts: string[] = token.split(".");

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
    const inputHeader: bwt.Header = createHeader({ kid: a.kid });
    const inputBody: bwt.Body = createBody();

    let token: string = a.stringify(inputHeader, inputBody);

    const parts: string[] = token.split(".");

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
    const inputHeader: bwt.Header = createHeader({ kid: a.kid });
    const inputBody: bwt.Body = createBody();

    let token: string = a.stringify(inputHeader, inputBody);

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
    const inputHeader: bwt.Header = createHeader({ kid: a.kid });
    const inputBody: bwt.Body = createBody();

    let token: string = a.stringify(inputHeader, inputBody);

    const parts: string[] = token.split(".");

    let corruptCiphertext: Uint8Array = encode(parts[1], "base64");

    corruptCiphertext[0] ^= 0x99;

    parts[1] = decode(corruptCiphertext, "base64");

    token = parts.join(".");

    assertEquals(b.parse(token), null);
  }
});

runIfMain(import.meta);
