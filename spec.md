# Better Web Token Spec

## Summary

The Better Web Token (BWT) scheme specifies a web token format, the
corresponding token generation, token verification, as well as key generation
and derivation procedures.

The JOSE standards and its popular manifestation JWT have numerous
[design flaws](https://www.chosenplaintext.ca/2015/03/31/jwt-algorithm-confusion.html) and [deployment pitfalls](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/#Pitfalls-and-Common-Attacks). In contrast, BWT
utilizes a fixed AEAD scheme, [XChaCha20-Poly1305](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-01#section-2), encapsulates all cryptographic
operations, and exposes only lean and simple APIs. By design, BWT aims to
minimize the possibility of deployment vulnerabilities.

## Design Goals

+ secure by default
+ simple to use
+ hard to misuse

## Prior Art

Over the years a number of JWT alternatives, [PASETO](https://paseto.io/), [Branca](https://branca.io/), have
been developed. BWT is most similar to Branca which also uses
[XChaCha20-Poly1305](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-01#section-2). In contrast to Branca BWT utilizes key pairs instead
of symmetric keys. This reduces the risk of impersonation. Another notable
difference in comparison to Branca is the requirement that every BWT token
expires.

XChaCha20-Poly1305 is a recently standardized, AEAD construction that requires
a 192-bit nonce which due to that length can be generated with a CSPRNG. This
approach is, given the PRNG is cryptographically secure, more robust than
common counter-based generation techniques usually used for shorter nonces.

## Token Format

Basically, a BWT token has the following textual shape `header.body.signature`.
All three token components are URL-safe base64 strings concatenated with
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

## Public Key Validation

A BWT key pair consists of a Curve25519 key pair, with the secret and public
keys having a length of 32, enriched with a 16-byte public key
identifier. BWT requires contributory behavior, therefore the following
low-order public keys are invalid and must be rejected by any BWT procedure.

```
[
  0000000000000000000000000000000000000000000000000000000000000000,
  0100000000000000000000000000000000000000000000000000000000000000,
  e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800,
  5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157,
  ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f,
  edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f,
  eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f,
  cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880,
  4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7,
  d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
  daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
  dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
]
```

Obtained from
[Daniel J. Bernstein's webpage on ECDH](https://cr.yp.to/ecdh.html#validate).

## Procedures

### Header Serialization

#### Procedure

**Inputs:** version, issuance ms timestamp (iat), expiry ms timestamp
(exp), public key identifier (kid), nonce

+ obtain a buffer by acquiring (allocate or require as additional input) 60
bytes of memory

+ set the buffer's byte range 0..3 to `0x42 0x57 0x54`

+ set the buffer's byte 3..4 of the buffer to the version input parameter

+ set the buffer's byte range 4..12 to the big-endian representation of iat

+ set the buffer's byte range 12..20 to the big-endian representation of exp

+ set the buffer's byte range 20..36 to the kid

+ set the buffer's byte range 36..60 to the nonce

**Outputs:** buffer

### Header Deserialization

#### Procedure

**Inputs:** buffer

+ obtain the version by reading the fourth byte of the buffer

+ obtain iat by reading the buffer's byte range 4..12 as a big-endian integer

+ obtain exp by reading the buffer's byte range 12..20 as a big-endian integer

+ obtain the kid from the buffer's byte range 20..36

+ obtain the nonce from the buffer's byte range 36..60

**Outputs:** version, issuance ms timestamp (iat), expiry ms timestamp
(exp), public key identifier (kid), nonce

### Key Pair Generation

A BWT key pair is essentially a Curve25519 key pair enriched by a 16-byte
public key identifier (kid).

#### Procedure

**Inputs:** none

+ obtain a seed by generating 32 bytes from a CSPRNG

+ obtain the secret key by clearing bit 0, 1, 2, 255 and setting bit 254 of the
seed

+ zero out the seed memory

+ obtain the public key by performing a Curve25519 scalar multiplication of the
secret key and the constant value 9

+ assert that the public key is not among the set defined in
[Public Key Validation](#public-key-validation)
  
  + if the public key is in fact of low order, the corresponding secret key 
  memory must be zeroed - thereafter, implementations are free to either
  fallback to another key pair generation attempt or return a null value

+ obtain the kid by generating 16 bytes from a CSPRNG

**Outputs:** secret key, public key, kid

### Shared Key Derivation

BWT uses [HChaCha20](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-01#section-2.2) to derive a shared key from a X25519 shared secret.

The secret and public key must have been generated using the procedure
specified in [Key Pair Generation](#key-pair-generation).

#### Procedure

**Inputs:** secret key, public key

+ assert that the public key is not among the set defined in
[Public Key Validation](#public-key-validation)

+ obtain the shared secret by performing X25519 with the secret and public key

+ create the shared key by applying [HChaCha20](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-01#section-2.2) with the shared secret, a 16-byte all-zero nonce, and the 16-byte binary representation of the UTF-8
string "BETTER_WEB_TOKEN" as a constant context value

+ zero out the shared secret memory

**Outputs:** shared key

### Token Generation

The token generation procedure takes the shared key between the issuing and
addressed peer as input, see [Shared Key Derivation](#shared-key-derivation)
for details.

Any unexpected state encountered during the following procedure (i.e. negative
asserts) must not raise an exception but rather return a null value.

#### Procedure

**Inputs:** shared key, version, issuance ms timestamp (iat),
expiry ms timestamp (exp), public key identifier (kid),
body (must be coercible to a JSON object)

+ assert that the version is an unsigned integer among the following set: 0

+ assert that iat is an unsigned integer less than or equal the current time

+ assert that exp is an unsigned integer greater than the current time

+ assert that kid has a byte length of 16

+ obtain a nonce by generating 24 bytes from a CSPRNG

+ obtain the additional authenticated data (aad) from the version, iat and
exp timestamps, the kid, and the nonce as defined in
[Header Serialization](#header-serialization)

+ assert that the aad has a byte length not greater than 18446744073709551615

+ obtain the JSON body by stringifying the body to a valid JSON object

+ obtain the plaintext by serializing the JSON body to its binary
representation assuming UTF-8 encoding

+ assert that the plaintext has a byte length not greater than 274877906880

+ obtain the ciphertext and signature by applying XChaCha20-Poly1305 with the
shared key, nonce, plaintext, and aad

+ zero out the plaintext memory

+ obtain the token by concatenating the URL-safe base64 representations of the
aad, ciphertext, and signature, in this order, with a dot

+ assert that the total token byte length is not greater than 4096

**Outputs:** token

### Token Verification

The token verification procedure takes the shared key between the issuing and
addressed peer as input, see [Shared Key Derivation](#shared-key-derivation)
for details.

Any unexpected state encountered during the following procedure (i.e. negative
asserts) must not raise an exception but rather return a null value.

#### Procedure

**Inputs:** shared key, token

+ assert that the token matches this regular expression:
`^QldU[A-Za-z0-9-_=]{76}\.[A-Za-z0-9-_=]{4,3990}\.[A-Za-z0-9-_=]{24}$`

+ split the token into three pieces on the dot character, discarding it

  + obtain the authenticated additional data (aad) by serializing the first
  part from a URL-safe base64 string to a buffer
  
  + assert that the aad has a byte length not greater than 18446744073709551615

  + obtain the ciphertext by serializing the second part from a URL-safe base64 string to a buffer
  
  + assert that the ciphertext has a byte length not greater than 274877906896

  + obtain the received tag by serializing the third part from a URL-safe base64 string to a buffer

+ obtain the version, issuance millisecond timestamp (iat), expiry millisecond timestamp
(exp), public key identifier (kid), and nonce by applying the
[Header Deserialization](#header-deserialization) procedure with the aad as
input

+ obtain the plaintext by applying XChaCha20-Poly1305 with the
shared key, nonce, ciphertext, aad, and received tag

+ obtain the JSON plaintext by deserializing the binary plaintext assuming
UTF-8 encoding

+ zero out the plaintext memory

+ obtain the body by parsing the JSON plaintext

+ assert that the body is an object

+ assert that the version is an unsigned integer among the following set: 0

+ assert that iat is an unsigned integer less than or equal the current time

+ assert that exp is an unsigned integer greater than the current time

+ assert that kid has a byte length of 16

**Outputs:** body, version, issuance ms timestamp (iat), expiry ms timestamp
(exp), public key identifier (kid)

## Test Vectors

TODO
