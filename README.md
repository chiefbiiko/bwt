# bwt

[![Travis](http://img.shields.io/travis/chiefbiiko/bwt.svg?style=flat)](http://travis-ci.org/chiefbiiko/bwt) [![AppVeyor](https://ci.appveyor.com/api/projects/status/github/chiefbiiko/bwt?branch=master&svg=true)](https://ci.appveyor.com/project/chiefbiiko/bwt)

## Import

...

## Usage

...

## TODOs

- Refactor to accepting a header and payload; with the header containing the
  `iss`, `aud`, `iat`, `kid`, `typ`, and `exp` claims and the nonce; making it the AAD

- Catch `JSON.stringify` errors (and return null) in the `stringify` method

- Decouple `stringify` and `parse` to standalone functions

- Enforce a max length on the ciphertext to prevent DoS attacks

  - `v8`'s string max length is `2^30 - 25`

## Pending Features

1. Enable usage of one parser for opening tokens from various issuers

## Pending Flaws, Security Considerations

- How to mitigate DoS attacks that target `POLY1305`?

- `iss`, `aud`, `iat`, `kid`, `typ`, and `exp` claims required? Probably yes.

- `throw` or `null` if secret/public key lengths are not correct?

- Is indicating the token type through a plain magic number a security threat?

- Does returning null before execution of the entire function body reveal any
  vulnerable information?

## Threat Mitigations

- No [cryptographic agility](https://tools.ietf.org/html/rfc7518#section-8.1)
  available to developers

- [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) only

- High-security scheme `AEAD_CHACHA20_POLY1305`

  - [RFC 8439](https://tools.ietf.org/html/rfc8439) compliant

  - No efficient cryptanalysis has been disclosed (reference date 2019-04-02)

- All `BWT`s expire - `exp` claim is required to be a finite number
