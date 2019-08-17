import * as BWT from "./mod.ts";

const a = BWT.generateKeys() as any;
const b = BWT.generateKeys() as any;

a.stringify = BWT.stringifier(a.sk, { name: "bob", kid: b.kid, pk: b.pk });

b.parse = BWT.parser(b.sk, { name: "alice", kid: a.kid, pk: a.pk });

const now = Date.now();
const iat = now;
const exp = now + 1000;

const token = a.stringify(
  { typ: "BWTv0", iat, exp, kid: a.kid },
  { info: "jwt sucks" }
);

const contents = b.parse(token);

console.log("bob got this info:", contents.payload.info);
