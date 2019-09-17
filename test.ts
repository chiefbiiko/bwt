import { test, runIfMain } from "https://deno.land/std/testing/mod.ts";
import {
  assertEquals,
  assertThrows
} from "https://deno.land/std/testing/asserts.ts";
import { encode, decode } from "https://denopkg.com/chief/std-encoding/mod.ts";

import * as bwt from "./mod.ts";

function createHeader(source: { [key: string]: any } = {}): bwt.Header {
  return {
    typ: bwt.Typ.BWTv0,
    iat: Date.now(),
    exp: Date.now() + 419,
    kid: source.kid,
    ...source
  };
}

function createBody(...sources: bwt.Body[]): bwt.Body {
  return { fraud: "fraud", ...sources };
}

interface Peer {
  name: string;
  kid: Uint8Array;
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  stringify?: bwt.Stringify;
  parse?: bwt.Parse;
}

const a: Peer = { ...bwt.generateKeyPair(), stringify: null, name: "alice" };
const b: Peer = { ...bwt.generateKeyPair(), parse: null, name: "bob" };
const c: Peer = { ...bwt.generateKeyPair(), stringify: null, name: "chief" };

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

    const chiefInputHeader: bwt.Header = createHeader({ kid: c.kid });

    const inputBody: bwt.Body = createBody();

    const aliceToken: string = a.stringify(aliceInputHeader, inputBody);

    const chiefToken: string = c.stringify(chiefInputHeader, inputBody);

    const fromAlice: bwt.Contents = b.parse(aliceToken);

    const fromChiefbiiko: bwt.Contents = b.parse(chiefToken);

    assertEquals(fromAlice.header, aliceInputHeader);
    assertEquals(fromAlice.body, inputBody);
    assertEquals(fromChiefbiiko.header, chiefInputHeader);
    assertEquals(fromChiefbiiko.body, inputBody);
  }
});

test({
  name: "createStringify throws if ownSecretKey is invalid",
  fn(): void {
    assertThrows(
      (): void => {
        bwt.createStringify(new Uint8Array(bwt.SECRET_KEY_BYTES - 1), {
          publicKey: new Uint8Array(bwt.PUBLIC_KEY_BYTES),
          kid: new Uint8Array(bwt.KID_BYTES)
        });
      },
      TypeError,
      "invalid secret key"
    );
  }
});

test({
  name: "createStringify throws if peerPublicKey.publicKey is invalid",
  fn(): void {
    assertThrows(
      (): void => {
        bwt.createStringify(new Uint8Array(bwt.SECRET_KEY_BYTES), {
          publicKey: new Uint8Array(bwt.PUBLIC_KEY_BYTES - 1),
          kid: new Uint8Array(bwt.KID_BYTES)
        });
      },
      TypeError,
      "invalid peer public key"
    );
  }
});

test({
  name: "createStringify throws if peerPublicKey.kid is invalid",
  fn(): void {
    assertThrows(
      (): void => {
        bwt.createStringify(new Uint8Array(bwt.SECRET_KEY_BYTES), {
          publicKey: new Uint8Array(bwt.PUBLIC_KEY_BYTES),
          kid: new Uint8Array(bwt.KID_BYTES - 1)
        });
      },
      TypeError,
      "invalid peer public key"
    );
  }
});

test({
  name: "createParse throws if ownSecretKey is invalid",
  fn(): void {
    assertThrows(
      (): void => {
        bwt.createParse(Uint8Array.from([1, 2, 3]));
      },
      TypeError,
      "invalid secret key"
    );
  }
});

test({
  name: "createParse throws if peerPublicKey.publicKey is invalid",
  fn(): void {
    assertThrows(
      (): void => {
        bwt.createParse(new Uint8Array(bwt.SECRET_KEY_BYTES), {
          publicKey: new Uint8Array(bwt.PUBLIC_KEY_BYTES - 1),
          kid: new Uint8Array(bwt.KID_BYTES)
        });
      },
      TypeError,
      "invalid peer public keys"
    );
  }
});

test({
  name: "createParse throws if peerPublicKey.kid is invalid",
  fn(): void {
    assertThrows(
      (): void => {
        bwt.createParse(new Uint8Array(bwt.SECRET_KEY_BYTES), {
          publicKey: new Uint8Array(bwt.PUBLIC_KEY_BYTES),
          kid: new Uint8Array(bwt.KID_BYTES - 1)
        });
      },
      TypeError,
      "invalid peer public keys"
    );
  }
});

test({
  name: "createParse throws if no peer public keys are provided",
  fn(): void {
    assertThrows(
      (): void => {
        bwt.createParse(new Uint8Array(bwt.SECRET_KEY_BYTES));
      },
      TypeError,
      "no peer public keys provided"
    );
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
    const inputHeader: bwt.Header = createHeader({ typ: 255, kid: a.kid });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if kid is null",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ kid: null });

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
    const inputHeader: bwt.Header = createHeader({ iat: NaN, kid: a.kid });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if iat is Infinity",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ iat: Infinity, kid: a.kid });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if iat is null",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ iat: null, kid: a.kid });

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
    const inputHeader: bwt.Header = createHeader({ exp: NaN, kid: a.kid });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if exp is Infinity",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ exp: Infinity, kid: a.kid });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if exp is null",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({ exp: null, kid: a.kid });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "stringify nulls if exp is due",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({
      exp: Date.now() - 1,
      kid: a.kid
    });

    assertEquals(a.stringify(inputHeader, createBody()), null);
  }
});

test({
  name: "parse nulls if kid is unknown",
  fn(): void {
    const inputHeader: bwt.Header = createHeader({
      kid: encode("deadbeefdeadbeef", "utf8")
    });

    const token: string = a.stringify(inputHeader, createBody());

    assertEquals(b.parse(token), null);
  }
});

test({
  name: "parse nulls if exp is due",
  fn() {
    const exp: number = Date.now() + 10;

    const token: string = a.stringify(
      createHeader({ kid: a.kid, exp }),
      createBody()
    );

    assertEquals(typeof token, "string");

    while (Date.now() < exp) {}

    assertEquals(b.parse(token), null);
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
