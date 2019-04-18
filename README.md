# bwt

[![Travis](http://img.shields.io/travis/chiefbiiko/bwt.svg?style=flat)](http://travis-ci.org/chiefbiiko/bwt) [![AppVeyor](https://ci.appveyor.com/api/projects/status/github/chiefbiiko/bwt?branch=master&svg=true)](https://ci.appveyor.com/project/chiefbiiko/bwt)

## Import

...

## Usage

...

## TODOs

- toss `aud` and `iss`! (Rename `PeerPublicKey.iss?` => `PeerPublicKey.issuer?` bc no need 2 shortn it bc its not sent thru the wire no more)

- cache computed shared secrets in the factory in a `Map<kid,sharedSecret>`

## Pending Flaws, Security Considerations

- How to mitigate DoS attacks that target `POLY1305`? -> overall size cap, done

- Does having these in the plain AAD (`iat`, `kid`, `typ`, and `exp` claims) lead to any vulnerabilities?

## Threat Mitigations

- No [cryptographic agility](https://tools.ietf.org/html/rfc7518#section-8.1)
  available to developers

- [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) only

- High-security scheme `AEAD_CHACHA20_POLY1305`

  - [RFC 8439](https://tools.ietf.org/html/rfc8439) compliant

  - No efficient cryptanalysis has been disclosed (reference date 2019-04-02)

- `BWT`s require a fixed set of metadata claims - no opting-out
