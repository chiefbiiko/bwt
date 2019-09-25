# Better Web Token Spec

## Summary

The Better Web Token (BWT) scheme specifies a web token format, the 
corresponding token generation, token verification, as well as key generation 
and derivation procedures.

The JOSE standards and its popular manifestation JWT have numerous 
[design flaws](🔮) and [deployment pitfalls](🔮). In contrast, BWT utilizes a 
fixed AEAD scheme, [XChaCha20-Poly1305](🔮), encapsulates all cryptographic 
operations, and exposes only lean and simple APIs. By design, BWT aims to 
minimize the possibility of deployment vulnerabilities.

## Design Goals

+ secure by default
+ simple to use
+ hard to misuse

## Prior Art

Over the years a number of JWT alternatives, [PASETO](🔮), [Branca](🔮), have 
been developed. BWT is most similar to Branca which also uses
[XChaCha20-Poly1305](🔮). In contrast to Branca BWT utilizes key pairs instead
of symmetric keys. This reduces the risk of impersonation. Another notable
difference in comparison to Branca is the requirement that every BWT token
expires.

XChaCha20-Poly1305 is a well-analyzed, nonce-misuse-resistant, recently 
standardized, AEAD construction that requires a 192-bit nonce which due to that 
length can be generated with a CSPRNG. This approach is, given the PRNG is 
cryptographically secure, more robust than common counter-based generation 
techniques usually used for shorter nonces.

## Token Format

Basically, a BWT token has the following textual shape `header.body.signature`.
All three token components are base64-encoded (URL-safe) and concatenated with 
a dot. The header basically encompasses the AEAD construct's additional 
authenticated data. The body part represents the actual ciphertext, whereas the 
signature is the corresponding Poly1305 MAC.

Find the binary format of a header depicted below.

|Byte Range|Content|
------|-------|
`0..3`  | `0x42 0x57 0x54`
`3`     | version
`4..12` | big-endian issuance ms timestamp
`12..20`| big-endian expiry ms timestamp
`20..36`| issuer kid
`36..60`| nonce

## Key Pair Generation

A BWT key pair is essentially a Curve25519 key pair enriched by a 16-byte 
public key identifier (kid).

**Procedure**

Inputs: none

+ generate 32 cryptographically secure pseudo random bytes as a seed value

+ create the secret key by clearing bit 0, 1, 2, 255 and setting bit 254 of the 
seed

+ create the public key by performing a Curve25519 scalar multiplication of the 
secret key and the constant value 9

+ create the kid as 16 cryptographically secure pseudo random bytes

Outputs: secret key, public key, kid

## Shared Key Derivation

BWT uses HChaCha20 to derive a shared key from a Curve25519 shared secret.

**Procedure**

Inputs: secret key, public key

+ reject low-order public keys?

+ obtain a shared secret by performing a Curve25519 scalar multiplication of 
the secret and public key

+ create the shared key by applying HChaCha20 with the shared secret, a nonce 
value of zero, and the 16-byte binary counterpart of the UTF-8 string "BETTER_WEB_TOKEN" as a constant context value

Outputs: shared key

## Token Generation

## Token Verification

## Test Vectors
