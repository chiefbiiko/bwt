# bwt

[![Travis](http://img.shields.io/travis/chiefbiiko/bwt.svg?style=flat)](http://travis-ci.org/chiefbiiko/bwt) [![AppVeyor](https://ci.appveyor.com/api/projects/status/github/chiefbiiko/bwt?branch=master&svg=true)](https://ci.appveyor.com/project/chiefbiiko/bwt)

## Import

...

## Usage

...

## TODOs

- figure out `kid`, peer public key, just key encoding handling

## Pending Security Considerations

- Does having these in the plain AAD (`iat`, `kid`, `typ`, and `exp` claims) lead to any vulnerabilities?

## Design

- [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) only
  - High-security `AEAD_CHACHA20_POLY1305` scheme
  - [RFC 8439](https://tools.ietf.org/html/rfc8439) compliant
  - `BWT` tokens are encrypted and authenticated
  
- `BWT`s require a fixed set of metadata claims - no opting-out

- the de/serialization functions exposed never `throw` exceptions in order not to leak any vulnerable information. In case an operation encounters unexpected state, `null` is returned instead.
