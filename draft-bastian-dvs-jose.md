---
title: "Designated Verifier Signatures for JOSE"
abbrev: "DVS for JOSE"
category: info

docname: draft-bastian-dvs-jose-latest
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
  github: "paulbastian/draft-bastian-dvs-jose"
  latest: "https://paulbastian.github.io/draft-bastian-dvs-jose/draft-bastian-dvs-jose.html"

author:
 -
    fullname: Paul Bastian
    organization: Bundesdruckerei GmbH
    email: bastianpaul@googlemail.com

 -
    fullname: Micha Kraus
    organization: Bundesdruckerei GmbH

normative:
  RFC7515: RFC7515
  RFC7517: RFC7517
  RFC7518: RFC7518
  RFC9180: RFC9180

informative:
  HPKE-IANA:
    author:
    org: IANA
    title: Hybrid Public Key Encryption (HPKE) IANA Registry
    target: https://www.iana.org/assignments/hpke/hpke.xhtml
    date: October 2023


--- abstract

This specification defines designated verifier signatures for JOSE and defines algorithms that use a combination of key agreement and MACs.

--- middle

# Introduction

Designated verifier signatures (DVS) are signature schemes in which signatures are generated, that can only be verified a particular party. Unlike conventional digital signature schemes like ECDSA, this enables repudiable signatures.

This specification describes a general structure for designated verifier signature schemes and specified a set of instantiations that use a combination of an ECDH key exchange with an HMAC.

This specification and all described algorithms should respect the efforts for (Fully Specified Algorithms)[https://www.ietf.org/archive/id/draft-jones-jose-fully-specified-algorithms-00.html].

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

DVS uses the following notation:

TODO

DVS rely on the following primitives:

TODO

# Designated Verifier Signatures

A designated verifier signature requires three components for an algorithm:

1. a Diffie-Hellman Key Agreement (DHKA)
2. a Key Derivation Function (KDF)
3. a Message Authentication Code algorithm (MAC)

In general, these parameters are chosen by the Signing Party. These parameters need to be communicated to the Verifying Party before the generation of a Designated Verifier Signature.

## Signature Generation

The generation of the Designated Verifier Signature takes the private key of the Signing Party, the public key of the Verifying Party and the message as inputs. The retrieval and communication of the Verifying Party's public key is out of scope of this specification and subject to the implementing protocols.

The generation of the signature follows these steps:

1. Perform the key agreement as defined by the DHKA algorithm
  - use the specified elliptic curve to generate a key pair and set the `epk`
  - use the Verifier's public key defined by `kid` to perform the key agreement
  - optionally provide a certificate chain defined by `x5c`
2. Extract and expand the shared secret as defined by KDF algorithm
  - use the output from the key agreement as an input for the key derivation algorithm
  - derive the MAC key
3. Generate a MAC as defined by MAC algorithm
  - use the output from the key derivation algorithm as an input for the MAC algorithm
  - use the `JWS Signing Input` as defined in Section 5.1 if {{RFC7515}} as the `message` input for the MAC algorithm
  - generate the MAC

The verification of signature follows these steps:

1. Perform key agreement as defined by the DHKA algorithm
  - use the specified elliptic curve to generate an ephemeral key pair and set the `kid`
  - provide the public key `kid` to the Signing Party
  - use the Signing Party's public key defined by `epk` and perform the key agreement
  - optionally validate the certificate chain defined by `x5c`
2. Extract and expand the shared secret as defined by KDF algorithm
  - use the output from the key agreement as an input for the key derivation algorithm
  - derive the MAC key
3. Generate a MAC as defined by MAC algorithm
  - use the output from the key derivation algorithm as an input for the MAC algorithm
  - generate the MAC
4. Compare the generated MAC with the signature value



# Designated Verifier Signatures using HPKE

This section describes a simple designated verifier signature scheme based on Hybrid Public Key Encryption (HPKE) {{RFC9180}} in auth mode.
It reuses the authentication scheme underlying the AEAD algorithm in use, while using the KEM to establish a one-time authentication key from a pair of KEM public keys.
This scheme was described in early specification drafts of HPKE {{RFC9180}}

## Signature Generation

To create a signature, the sender simply calls the single-shot `Seal()` method with an empty plaintext value and the message to be signed as AAD.
This produces an encoded key enc and a ciphertext value that contains only the AAD tag. The signature value is the concatenation of the encoded key and the AAD tag.


Input:

 * `skS`: private key of the Signing Party
 * `pkR`: public key of the Verifying Party
 * `msg`: JWS Signing Input

Steps:

1. Call `enc`, `ct` = `SealAuth(pkR, info, aad, pt, skS)` with
   * `info` = ""
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
 * `signature`: JWS Signature octet string

Steps:

1. Decode `enc` \|\| `ct` = `signature` by length of `enc` and `ct`. See [HPKE-IANA] for length of ct and enc.
2. Call `pt` = `OpenAuth(enc, skR, info, aad, ct, pkS)` with
   * `info` = ""
   * `aad` = msg
3. the signature is valid, when `OpenAuth()` returns `pt` = "" with no authentication exception

NOTE: `ct` contains only a tag. It's length depends on the AEAD algorithm (see Nt values in RFC9180 chapter 7.3.)

## Signature Suites
Algorithms MUST follow the naming `DVS-HPKE-<Mode>-<KEM>-<KDF>-<AEAD>`.
"Mode" is Auth (PSKAuth could also be used).
The "KEM", "KDF", and "AEAD" values are chosen from the HPKE IANA registry [HPKE-IANA].


# Designated Verifier Signatures for JOSE

Designated Verifier Signatures behave like a digital signature as described in Section 3 of {{RFC7518}} and are intended for use in JSON Web Signatures (JWS) as described in {{RFC7515}}. The Generating Party performs the `Message Signature or MAC Computation` as defined by Section 5.1 of {{RFC7515}}. The Verifying Party performs the `Message Signature or MAC Validation` as defined by Section 5.2 of {{RFC7515}}.

The following JWS headers are used to convey Designated Verifier Signatures for JOSE:

 * `alg` : The algorithm parameter describes the chosen signature suite, for example the ones described in (#suites)
 * `jwk` : The `jwk` parameter represents the encoded public key of the Signing Party for the use in the DHKA algorithm as a JSON Web Key according to {{RFC7517}}. It MUST contain only public key parameters and SHOULD contain only the minimum JWK parameters necessary to represent the key. Usage of this parameter MUST be supported.
 * `x5c` : The `x5c` parameter represents the encoded certificate chain and its leaf public key of the Signing Party for the use in the DHKA algorithm as a X.509 certificate chain according to {{RFC7517}}. Alternatively, the Signing Party may use "x5t", x5t#S256" or "x5u". Usage of this parameter MAY be supported.
 * `rpk` : The `rpk` (recipient public key) parameter represents the encoded public key of the Verifying Party that was used in the DHKA algorithm as a JSON Web Key according to {{RFC7517}}. This parameter MUST be present.

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

# Signature Suites {#suites}

Algorithms MUST follow the naming `DVS-<DHKA>-<KDF>-<MAC>`.

This specification described instantiations of Designated Verifier Signatures using specific algorithm combinations:

~~~ ascii-art
+-----------------------+-----------------------------+----------------+
| Algorithm Name        | Algorithm Description       |                |
|                       |                             | Requirements   |
+-----------------------+-----------------------------+----------------+
| DVS-P256-SHA256-HS256 | ECDH using NIST P-256,      | Optional       |
|                       | HKDF using SHA-256 and      |                |
|                       | HMAC using SHA-256          |                |
+-----------------------+-----------------------------+----------------+
| DVS-HPKE-Auth-X25519  | DVS based on HPKE using     |                |
| -SHA256               | DHKEM(X25519, HKDF-SHA256)  |   Optional     |
| -ChaCha20Poly1305     | HKDF-SHA256 KDF and         |                |
|                       | ChaCha20Poly1305 AEAD       |                |
+-----------------------+-----------------------------+----------------+
| DVS-HPKE-Auth-P256    | DVS based on HPKE using     |                |
| -SHA256-AES128GCM     | DHKEM(P-256, HKDF-SHA256)   |   Optional     |
|                       | HKDF-SHA256 KDF and         |                |
|                       | AES-128-GCM AEAD            |                |
+-----------------------+-----------------------------+----------------+

~~~

# Security Considerations

TODO Security


# IANA Considerations

Define:

- `rpk` header parameter
- alg values for DVS-P256-SHA256-HS256 and some more


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.