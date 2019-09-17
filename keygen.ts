import { decode } from "https://denopkg.com/chiefbiiko/std-encoding/mod.ts";
import { generateKeyPair, KeyPair } from "./mod.ts";

function main(): void {
  const keyPair: KeyPair = generateKeyPair();

  const publicKey: string = decode(keyPair.publicKey, "base64");

  const kid: string = decode(keyPair.kid, "base64");

  const stringPeerPublicKey: string = JSON.stringify(
    { publicKey, kid, name: Deno.args[1] },
    null,
    2
  );

  let secretKey: string = decode(keyPair.secretKey, "base64");

  let stringKeyPair: string = JSON.stringify(
    { secretKey, publicKey, kid },
    null,
    2
  );

  keyPair.secretKey.fill(0x00, 0, keyPair.secretKey.byteLength);
  secretKey = null;

  console.log(`key pair\n${stringKeyPair}`);
  console.log(`peer public key\n${stringPeerPublicKey}`);

  stringKeyPair = null;
}

main();
