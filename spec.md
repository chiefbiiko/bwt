# Better Web Token Spec

## Summary

The Better Web Token (BWT) scheme specifies a web token format as well as the
corresponding generation and verification procedures.

BWT aims to prevent any [ambiguities and flaws](🔮) incorporated in the
[JOSE standards](🔮) by two main guiding principles:

* cryptographic mechanisms cannot be influenced by a user

* secure by default - i.e. any token is encrypted and authenticated

In addition to making BWT rather foolproof the above guidelines yield lean and
simple APIs for the token generation and verification procedures. In sum, these  
design basics minimize the possibility of deployment vulnerabilities.

This document defines the BWT message format, as well as the token generation
and token verification procedures.

## Introduction

Web tokens are omnipresent nowadays, but the JOSE standards and its popular
manifestation JWT are known to have numerous [design flaws](🔮) and
[deployment pitfalls](🔮).

Over the years a number of alternatives, [PASETO](🔮), [Branca](🔮), have been
developed. BWT is most similar to Branca which also uses
[XChaCha20-Poly1305](🔮). In contrast to Branca BWT utilizes key pairs instead
of symmetric keys. This reduces the risk of impersonation. Another notable
difference in comparison to Branca is the requirement that every BWT token
expires.

XChaCha20-Poly1305 is a well-analyzed nonce-misuse-resistant AEAD construction
that requires a 192-bit nonce which due to that length can be generated with a
CSPRNG. This approach is, given the PRNG is cryptographically secure, more
robust than common counter-based generation techniques for shorter nonces.

The BWT generation and verification procedures encapsulate all cryptographic
operations. Application developers cannot select the algorithms utilized, all
they need to take care of is key management.

## Design Goals

+ secure by default
+ simple to use
+ hard to misuse

## Token Format

Basically, a BWT token has the following textual shape `header.body.signature`.
All three token components are base64-encoded and concatenated with a dot. The
header basically encompasses the AEAD construct's additional authenticated data.
The body part represents the actual ciphertext, whereas the signature is the
corresponding Poly1305 MAC.

|Range|Content|
------|-------|
0..3  | `0x42 0x57 0x54`
3     | `u8` version
4..12 | issuance ms timestamp
12..20| expiry ms timestamp
20..36| 16-byte public key identifier of the issuing peer
36..60| 24-byte nonce

...

## Token Generation

## Token Verification

## Test Vectors
