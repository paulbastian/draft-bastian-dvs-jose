---
title: "Designated Verifier Signatures for JOSE"
abbrev: "DVS for JOSE"
category: info

docname: draft-bastian-jose-dvs-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Javascript Object Signing and Encryption"
keyword:
 - JOSE
 - JWS
 - designated verifier signature
 - HPKE
venue:
  group: "Javascript Object Signing and Encryption"
  type: "Working Group"
  mail: "jose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/jose/"
  github: "paulbastian/draft-bastian-jose-dvs"
  latest: "https://paulbastian.github.io/draft-bastian-jose-dvs/draft-bastian-jose-dvs.html"

author:
 -
    fullname: Paul Bastian
    email: bastianpaul@googlemail.com

 -
    fullname: Micha Kraus
    email: kraus.micha@gmail.com

normative:
  RFC7515: RFC7515
  RFC7517: RFC7517
  RFC7518: RFC7518
  RFC9180: RFC9180
  BSI-TR-03111:
    title: "Technical Guideline BSI TR-03111: Elliptic Curve Cryptography, Version 2.10"
    target: https://www.bsi.bund.de/dok/TR-03111-en
    date: June 2018


informative:
  HPKE-IANA:
    title: Hybrid Public Key Encryption (HPKE) IANA Registry
    target: https://www.iana.org/assignments/hpke/hpke.xhtml
    date: October 2023
  ISO-18013-5:
    title: "ISO/IEC 18013-5:2021, Personal identification — ISO-compliant driving licence, Part 5: Mobile driving licence (mDL) application"
    target: https://www.iso.org/standard/69084.html
    date: September 2021




--- abstract

This specification defines structures and algorithm descriptions for the use of designated verifier signatures, based on a combination of Key Agreement and Message Authentication Code, with JOSE.

--- middle

# Introduction

Designated verifier signatures (DVS) are signature schemes in which signatures are generated, that can only be verified a particular party. Unlike conventional digital signature schemes like ECDSA, this enables repudiable signatures.

This specification describes a general structure for designated verifier signature schemes and specified a set of instantiations that use a combination of an KA-DH (Diffie-Hellman key aggrement) with an MAC (Message Authentication Code algorithm).

The combination of ECKA-DH and MAC is a established mechanism and used, for example, in the mobile driving licence (mDL) application, specified in {{ISO-18013-5}}.

This specification and all described algorithms should respect the efforts for [Fully Specified Algorithms](https://www.ietf.org/archive/id/draft-jones-jose-fully-specified-algorithms-00.html).

This algorithm is intended for use with digital credentials ecosystems, including the Issuer-Holder-Verifier model described by W3C VCDM or IETF SD-JWT-VC.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

The draft uses "JSON Web Signature", "JOSE Header", "JWS Signature", "JWS Signing Input" as defined by {{RFC7515}}.

Signing Party:
: The Party that performs the key agreement first and generates the MAC. Similar to a Signer.

Verifying Party:
: The Party that performs the key agreement second, generates the MAC and compares it to a given value. Similar to a Verifier.

# Cryptographic Dependencies

DVS rely on the following primitives:

- A Diffie-Hellman Key Agreement (KA-DH), for example ECKA-DH defined in {{BSI-TR-03111}}:
    - `DH(skX, pkY)`: Perform a non-interactive Diffie-Hellman exchange using the private key `skX` and public key `pkY` to produce a Diffie-Hellman shared secret of length Ndh. This function can raise a ValidationError.
    - `Ndh`: The length in bytes of a Diffie-Hellman shared secret produced by `DH()`.
    - `Nsk`: The length in bytes of a Diffie-Hellman private key.

- A key derivation function (KDF), for example HKDF defined in TODO:
    - `Extract(salt, ikm)`: Extract a pseudorandom key of fixed length Nh bytes from input keying material `ikm` and an optional byte string `salt`.
    - `Expand(prk, info, L)`: Expand a pseudorandom key `prk` using optional string `info` into `L` bytes of output keying material.
    - `Nh`: The output size of the Extract() function in bytes.

- A Message Authentication Code algorithm (MAC), for example HMAC defined in TODO:
    - `MacSign(k, i)`: Returns an authenticated tag for the given input `i` and key `k`.
    - `Nk`: The length in bytes of key `k`.

# Designated Verifier Signatures

A designated verifier signature requires three components for an algorithm:

1. a Diffie-Hellman Key Agreement (DHKA)
2. a Key Derivation Function (KDF)
3. a Message Authentication Code algorithm (MAC)

In general, these parameters are chosen by the Signing Party. These parameters need to be communicated to the Verifying Party before the generation of a Designated Verifier Signature.


## Signature Generation

The generation of the Designated Verifier Signature takes the private key of the Signing Party, the public key of the Verifying Party and the message as inputs. The retrieval and communication of the Verifying Party's public key is out of scope of this specification and subject to the implementing protocols.

Input:

 * `skS`: private key of the Signing Party
 * `pkR`: public key of the Verifying Party
 * `msg`: JWS Signing Input
 * `salt` : Salt for key derivation
 * `info` : optional info for key derivation

Function:

~~~
def dvsSign(skS, pkR, msg, salt= "", info = "DVS-1")

    dh =  DH(skS, pkR)
    prk = Extract(salt, dh)
    k = Expand(prk, info, Nk)
    signature = MacSign(k, msg)
    return signature
~~~

## Signature Verification

The generation of the Designated Verifier Signature takes the private key of the Signing Party, the public key of the Verifying Party and the message as inputs. The retrieval and communication of the Verifying Party's public key is out of scope of this specification and subject to the implementing protocols.

Input:

 * `skR`: private key of the Verifying Party
 * `pkS`: public key of the Signing Party
 * `msg`: JWS Signing Input
 * `salt` : Salt for key derivation
 * `info` : optional info for key derivation
 * `signature` : the Message Authentication Code

Function:

~~~
def dvsVerify(skR, pkS, msg, salt = "", info = "DVS-1", signature)

    dh =  DH(skR, pkS)
    prk = Extract(salt, dh)
    k = Expand(prk, info, Nk)
    signature' = MacSign(k, msg)
    if signature != signature':
    raise Exception("Designated Verifier Signature invalid")
    return
~~~

## Signature Suites {#generic_suites}
Algorithms MUST follow the naming `DVS-<DHKA>-<KDF>-<MAC>`.

# Designated Verifier Signatures for JOSE

Designated Verifier Signatures behave like a digital signature as described in Section 3 of {{RFC7518}} and are intended for use in JSON Web Signatures (JWS) as described in {{RFC7515}}. The Generating Party performs the `Message Signature or MAC Computation` as defined by Section 5.1 of {{RFC7515}}. The Verifying Party performs the `Message Signature or MAC Validation` as defined by Section 5.2 of {{RFC7515}}.

The following JWS headers are used to convey Designated Verifier Signatures for JOSE:

 * `alg` : REQUIRED. The algorithm parameter describes the chosen signature suite, for example the ones described in (#generic_suites) and (#hpke_suites).
 * `rpk` : REQUIRED. The `rpk` (recipient public key) parameter represents the encoded public key of the Verifying Party that was used in the DHKA algorithm as a JSON Web Key according to {{RFC7517}}. This parameter MUST be present.
 * `nonce` : OPTIONAL. The `nonce` may be provided by the Verifying Party additional to it's public key and ensure additional freshness of the signature. If provided, the Signing Party SHOULD add the `nonce` to the header.

The Signing Party may use existing JWS header parameters like `x5c`, `jwk` or `kid` to represent or reference it's public key according to {{RFC7517}}.

## Example JWT

The JWT/JWS header:

~~~
{
    "typ" : "JWT",
    "alg" : "DVS-P256-SHA256-HS256",
    "jwk" : <JWK of the Signing Party>,
    "rpk" : <JWK of Verifying Party>
}
~~~

The JWT/JWS payload:

~~~
{
    "iss" : "https://example.as.com",
    "iat" : "1701870613",
    "given_name" : "Erika",
    "family_name" : "Mustermann"
}
~~~

The JWT/JWS signature:

~~~
base64-encoded MAC
~~~

This specification described instantiations of Designated Verifier Signatures using specific algorithm combinations:

~~~ ascii-art
+-----------------------+-----------------------------+----------------+
| Algorithm Name        | Algorithm Description       |                |
|                       |                             | Requirements   |
+-----------------------+-----------------------------+----------------+
| DVS-P256-SHA256-HS256 | ECDH using NIST P-256,      |   Optional     |
|                       | HKDF using SHA-256 and      |                |
|                       | HMAC using SHA-256          |                |
+-----------------------+-----------------------------+----------------+
| DVS-HPKE-Auth-X25519  | DVS based on HPKE using     |                |
| -SHA256               | DHKEM(X25519, HKDF-SHA256)  |  Optional      |
| -ChaCha20Poly1305     | HKDF-SHA256 KDF and         |  (Appendix A)  |
|                       | ChaCha20Poly1305 AEAD       |                |
+-----------------------+-----------------------------+----------------+
| DVS-HPKE-Auth-P256    | DVS based on HPKE using     |                |
| -SHA256-AES128GCM     | DHKEM(P-256, HKDF-SHA256)   |   Optional     |
|                       | HKDF-SHA256 KDF and         |   (Appendix A) |
|                       | AES-128-GCM AEAD            |                |
+-----------------------+-----------------------------+----------------+
~~~

# Security Considerations

## Replay Attack Detection

- Verifying Party MUST ensure the freshness of signatures by utilizing ephemeral keys in `rpk` or by providing a nonce for `nonce`.

# IANA Considerations

Define:

- define new `rpk` header parameter
- alg values for DVS-P256-SHA256-HS256 and some more

--- back

# Designated Verifier Signatures using HPKE

This section describes a simple designated verifier signature scheme based on Hybrid Public Key Encryption (HPKE) {{RFC9180}} in auth mode.
It reuses the authentication scheme underlying the AEAD algorithm in use, while using the KEM to establish a one-time authentication key from a pair of KEM public keys.
This scheme was described in early specification drafts of HPKE {{RFC9180}}

## Cryptographic Dependencies

- An HPKE algorithm (for the HPKE variants):
- `SealAuth(pkR, info, aad, pt, skS)`: encrypts and authenticates single plaintext `pt` with associated data `aad` and context `info` using a private sender key `skS` and public receiver key `pkR`.
- `OpenAuth(enc, skR, info, aad, ct, pkS)`: decrypts ciphertext and tag `ct` with associated data `aad` and context `info` using a private receiver key `skR` and public sender key `pkS`.

## Signature Generation

To create a signature, the sender simply calls the single-shot `Seal()` method with an empty plaintext value and the message to be signed as AAD.
This produces an encoded key enc and a ciphertext value that contains only the AAD tag. The signature value is the concatenation of the encoded key and the AAD tag.

Input:

* `skS`: private key of the Signing Party
* `pkR`: public key of the Verifying Party
* `msg`: JWS Signing Input
* `info` : optional info for key derivation

Steps:

1. Call `enc`, `ct` = `SealAuth(pkR, info, aad, pt, skS)` with
* `aad` = `msg`
* `pt` = ""
2. JWS Signature is the octet string concatenation of (`enc` \|\| `ct`)

## Signature Verification

To verify a signature, the recipient extracts encoded key and the AAD tag from the signature value and calls the single-shor `Open()` with the provided ciphertext.
If the AEAD authentication passes, then the signature is valid.

Input:

* `skR`: private key of the Verifying Party
* `pkS`: public key of the Signing Party
* `msg`: JWS Signing Input
* `info` : optional info for key derivation
* `signature`: JWS Signature octet string

Steps:

1. Decode `enc` \|\| `ct` = `signature` by length of `enc` and `ct`. See {{HPKE-IANA}} for length of ct and enc.
2. Call `pt` = `OpenAuth(enc, skR, info, aad, ct, pkS)` with
* `aad` = msg
3. the signature is valid, when `OpenAuth()` returns `pt` = "" with no authentication exception

NOTE: `ct` contains only a tag. It's length depends on the AEAD algorithm (see Nt values in RFC9180 chapter 7.3.)

## Signature Suites {#hpke_suites}
Algorithms MUST follow the naming `DVS-HPKE-<Mode>-<KEM>-<KDF>-<AEAD>`.
"Mode" is Auth (PSKAuth could also be used).
The "KEM", "KDF", and "AEAD" values are chosen from the HPKE IANA registry {{HPKE-IANA}}.


# Acknowledgments

Thanks to:

- Brian Campbell
- John Bradley


