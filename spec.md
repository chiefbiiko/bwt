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

## Header Serialization

TODO

## Header Deserialization

TODO

## Key Pair Generation

A BWT key pair is essentially a Curve25519 key pair enriched by a 16-byte 
public key identifier (kid).

**Procedure**

Inputs: none

+ obtain a seed by generating 32 bytes from a CSPRNG

+ create the secret key by clearing bit 0, 1, 2, 255 and setting bit 254 of the 
seed

+ zero out the seed memory

+ create the public key by performing a Curve25519 scalar multiplication of the 
secret key and the constant value 9

+ create the kid as 16 cryptographically secure pseudo random bytes

Outputs: secret key, public key, kid

## Shared Key Derivation

BWT uses HChaCha20 to derive a shared key from a [X25519](🔮) shared secret. To ensure contributory behavior the X25519 function must reject any public key 
that is among the following set:

```
TODO
```

Obtained from [djb's webpage on ECDH](https://cr.yp.to/ecdh.html#validate).

**Procedure**

Inputs: secret key, public key

+ reject any public key that is among the above set

+ obtain the shared secret by performing X25519 with the secret and public key

+ create the shared key by applying [HChaCha20](🔮) with the shared secret, a 
16-byte all-zero nonce, and the 16-byte binary representation of the UTF-8 
string "BETTER_WEB_TOKEN" as a constant context value

+ zero out the shared secret memory

Outputs: shared key

## Token Generation

The token generation procedure takes the shared key between the issuing and 
addressed peer as input, see [Shared Key Derivation](#shared-key-derivation) 
for details.

Any unexpected state encountered during the following procedure (e.g. negative 
asserts) must not raise an exception but rather return a null value.

**Procedure**

Inputs: shared key, version, issuance ms timestamp (iat), expiry ms timestamp 
(exp), public key identifier (kid), body (a JSON object)

+ assert that the version is an unsigned integer among the following set: 0

+ assert that iat is an unsigned integer less than or equal the current time

+ assert that exp is an unsigned integer greater than the current time

+ assert that kid has a byte length of 16

+ obtain a nonce by generating 24 bytes from a CSPRNG

+ obtain the additional authenticated data (aad) from the version, iat and 
exp timestamps, the kid, and the nonce as defined in 
[Header Serialization](#header-serialization)

+ obtain the plaintext by serializing the body JSON object to its binary 
representation assuming UTF-8 encoding

+ obtain the ciphertext and signature by applying XChaCha20-Poly1305 with the 
shared key, nonce, plaintext, and aad

+ obtain the token by concatenating the URL-safe base64 representations of the 
aad, ciphertext, and signature, in this order

+ assert that the total token byte length is not greater than 4096

Outputs: token

## Token Verification

...

Inputs: token

TODO

## Test Vectors

TODO
