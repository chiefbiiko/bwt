import * as BWT from "https://denopkg.com/chiefbiiko/bwt/mod.ts";

const alice = { ...BWT.generateKeys(), stringify: null };
const bob = { ...BWT.generateKeys(), parse: null };

alice.stringify = BWT.stringifier(alice.sk, { kid: bob.kid, pk: bob.pk });
bob.parse = BWT.parser(bob.sk, { kid: alice.kid, pk: alice.pk });

const iat = Date.now();
const exp = iat + 1000;

const token = alice.stringify(
  { typ: "BWTv0", kid: alice.kid, iat, exp },
  { info: "jwt sucks" }
);

const contents = bob.parse(token);

console.log("bob got this info:", contents.payload.info);
