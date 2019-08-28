import * as bwt from "https://denopkg.com/chiefbiiko/bwt/mod.ts";

const alice = { ...bwt.keys(), stringify: null };
const bob = { ...bwt.keys(), parse: null };

alice.stringify = bwt.stringifier(alice.secretKey, {
  kid: bob.kid,
  publicKey: bob.publicKey
});

bob.parse = bwt.parser(bob.secretKey, {
  kid: alice.kid,
  publicKey: alice.publicKey
});

const iat = Date.now();
const exp = iat + 1000;

const token = alice.stringify(
  { typ: "BWTv0", kid: alice.kid, iat, exp },
  { info: "jwt sucks" }
);

const contents = bob.parse(token);

console.log("bob got this info:", contents.body.info);
