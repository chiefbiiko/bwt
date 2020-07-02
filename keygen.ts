import { decode } from "https://denopkg.com/chiefbiiko/std-encoding/mod.ts";
import { generateKeyPair, KeyPair } from "./mod.ts";

function main(): void {
  let keyPair: KeyPair;
  let secretKey: string;
  let stringKeyPair: string;

  try {
    keyPair = generateKeyPair();

    const publicKey: string = decode(keyPair.publicKey, "base64url");

    const kid: string = decode(keyPair.kid, "base64url");

    const stringPeerPublicKey: string = JSON.stringify(
      { publicKey, kid, name: Deno.args[1] },
      null,
      2,
    );

    secretKey = decode(keyPair.secretKey, "base64url");

    stringKeyPair = JSON.stringify({ secretKey, publicKey, kid }, null, 2);

    console.log(`key pair\n${stringKeyPair}`);
    console.log(`peer public key\n${stringPeerPublicKey}`);
  } catch (err) {
    console.error(err.stack);
  } finally {
    keyPair.secretKey.fill(0x00, 0, keyPair.secretKey.byteLength);
    secretKey = null;
    stringKeyPair = null;
  }
}

main();
