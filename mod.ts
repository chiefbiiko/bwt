import {
  aeadChaCha20Poly1305Seal,
  aeadChaCha20Poly1305Open
} from "./../aead_chacha20_poly1305/aead_chacha20_poly1305.ts";
import { Curve25519 } from "./../curve25519/mod.ts";
import { hex2bytes, bytes2hex, toByteArray, fromByteArray } from "./util.ts";

export interface Payload {
  [key: string]: unknown;
}

export interface Authenticator {
  stringify(payload: Payload): string;
  parse(token: string): Payload;
}

export interface Curve25519Keys {
  ownSecretKey: Uint8Array;
  peerPublicKey: Uint8Array;
}

const CURVE25519: Curve25519 = new Curve25519();
const enc: TextEncoder = new TextEncoder();
const dec: TextDecoder = new TextDecoder();
const TAG_BYTES: number = 16;
const NONCE_BYTES: number = 12;

function nextNonce(): Uint8Array {
  return enc.encode(String(Date.now()).slice(-12));
}

// function toBase64(text: string): string {
  // return btoa(unescape(encodeURIComponent(text)));
  // return btoa(text);
// }

// function fromBase64(base64: string): string {
  // return atob(escape(decodeURIComponent(base64)));
  // return decodeURIComponent(escape(atob(base64)));
  // return atob(base64);
// }

function debug(...args) {
  console.error("\n[DEBUG]", ...args, "\n");
}

// btoa(unescape(encodeURIComponent(str)))
// atob(escape(decodeURIComponent(str)))

export function createAuthenticator({
  ownSecretKey,
  peerPublicKey
}: Curve25519Keys): Authenticator {
  const key: Uint8Array = CURVE25519.scalarMult(ownSecretKey, peerPublicKey);
  return {
    stringify(payload: Payload): string {
      const nonce: Uint8Array = nextNonce();
      debug("stringify nonce", nonce);
      const plaintext: Uint8Array = enc.encode(JSON.stringify(payload));
      debug("stringify plaintext", plaintext);
      const { ciphertext, tag } = aeadChaCha20Poly1305Seal(
        key,
        nonce,
        plaintext,
        nonce
      );
      debug("stringify ciphertext", ciphertext);
      debug("stringify tag", tag);
      // return btoa(`${dec.decode(tag)}${dec.decode(nonce)}${dec.decode(ciphertext)}`);
      // return btoa(
      //   unescape(
      //     encodeURIComponent(
      //       `${dec.decode(tag)}${dec.decode(nonce)}${dec.decode(ciphertext)}`
      //     )
      //   )
      // );
      // var dtag = dec.decode(tag)
      // var dnonce = dec.decode(nonce)
      // var dciphertext = dec.decode(ciphertext)
      // debug("stringify dtag", dtag, "dtag.length", dtag.length)
      // debug("stringify dnonce", dnonce, "dnonce.length", dnonce.length)
      // debug("stringify dciphertext", dciphertext, "dciphertext.length", dciphertext.length)
      // return `${dtag}${dnonce}${dciphertext}`;
      // return `${toBase64(dec.decode(nonce))}_${toBase64(dec.decode(tag))}_${toBase64(dec.decode(ciphertext))}`;
      // return `${bytes2hex(nonce)}_${bytes2hex(tag)}_${bytes2hex(ciphertext)}`;
      return `${fromByteArray(nonce)}.${fromByteArray(tag)}.${fromByteArray(ciphertext)}`;
    },
    parse(token: string): Payload {
      // const rebased: Uint8Array = enc.encode(atob(token));
      // const rebased: Uint8Array = enc.encode(
      //   atob(escape(decodeURIComponent(token)))
      // );
      // const rebased: Uint8Array = enc.encode(token);
      // const receivedTag: Uint8Array = rebased.subarray(0, TAG_BYTES);
      // debug("parse receivedTag", receivedTag);
      // const nonce: Uint8Array = rebased.subarray(
      //   TAG_BYTES,
      //   TAG_BYTES + NONCE_BYTES
      // );
      // debug("parse nonce", nonce);
      // const ciphertext: Uint8Array = rebased.subarray(
      //   TAG_BYTES + NONCE_BYTES,
      //   rebased.length
      // );
      // debug("parse ciphertext", ciphertext);
      const [nonce, receivedTag, ciphertext] = token.split(".")
        // .map((base64: string): Uint8Array => enc.encode(fromBase64(base64)));
        // .map(hex2bytes);
        .map(toByteArray);
      debug("parse nonce", nonce);
      debug("parse receivedTag", receivedTag);
      debug("parse ciphertext", ciphertext);
      const plaintext: Uint8Array = aeadChaCha20Poly1305Open(
        key,
        nonce,
        ciphertext,
        nonce,
        receivedTag
      );
      debug("parse plaintext", plaintext);
      if (!plaintext) {
        debug("null bc !plaintext");
        return null;
      }
      let payload: Payload;
      try {
        payload = JSON.parse(dec.decode(plaintext));
      } catch (_) {
        debug("null bc JSON.parse error");
        return null;
      }
      if (typeof payload.expires !== "number" || Date.now() > payload.expires) {
        debug("null bc expires");
        return null;
      }
      return payload;
    }
  };
}
