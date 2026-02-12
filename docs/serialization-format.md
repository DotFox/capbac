# CapBAC Serialization Format

This document describes the binary wire format for `CapBACCertificate` and `CapBACInvocation` tokens. Both use big-endian (network byte order) encoding via Java's `DataOutputStream`/`DataInputStream`.

## Overview

Every serialized token starts with a 1-byte **type tag** that distinguishes certificates from invocations:

| Type Tag | Value  | Token Type          |
|----------|--------|---------------------|
| `0x01`   | 1      | `CapBACCertificate` |
| `0x02`   | 2      | `CapBACInvocation`  |

Deserialization (`CapBACToken.fromBytes`) reads this tag first, strips it, and dispatches the remaining bytes to the appropriate `fromBytesPayload` method.

## BLS Scheme

The byte immediately after the type tag identifies the BLS scheme. The scheme determines public key and signature sizes:

| Scheme ID | Name      | Public Key Size | Signature Size |
|-----------|-----------|-----------------|----------------|
| `0x01`    | `MIN_PK`  | 48 bytes        | 96 bytes       |
| `0x02`    | `MIN_SIG` | 96 bytes        | 48 bytes       |

The `PrincipalId` is the raw bytes of a BLS public key, so its size matches the public key size of the scheme being used.

## Length-Prefixed Fields

Variable-length fields use a 4-byte big-endian `int32` length prefix followed by exactly that many bytes. This pattern is used for:

- Certificate chain entries
- PrincipalId fields (issuer, subject, invoker)
- Capability payloads
- The invocation body (in `CapBACInvocation` only)

The aggregate signature is **not** length-prefixed because its size is known from the scheme.

## CapBACCertificate

```
+--------+--------+----------------+---------------------------+-----+----------------------+
| type   | scheme | chain_count    | certificate[0..n-1]       | ... | aggregate_signature  |
| 1 byte | 1 byte | int32 (4 bytes)| (length-prefixed entries) |     | (scheme-dependent)   |
+--------+--------+----------------+---------------------------+-----+----------------------+
```

### Layout

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | `type` | `0x01` (certificate) |
| 1 | 1 | `scheme_id` | BLS scheme identifier (`0x01` or `0x02`) |
| 2 | 4 | `chain_count` | Number of certificates in the chain |
| 6 | variable | `certificates` | `chain_count` length-prefixed certificate entries |
| ... | 48 or 96 | `aggregate_signature` | BLS aggregate signature (size depends on scheme) |

Each certificate entry in the chain is serialized as:

```
+------------------+-------------------+
| cert_length      | cert_bytes        |
| int32 (4 bytes)  | (cert_length)     |
+------------------+-------------------+
```

### Pseudocode

```
write byte    0x01                    // type tag
write byte    scheme.id               // scheme
write int32   certificates.length     // chain count
for each certificate:
    cert_bytes = certificate.toBytes()
    write int32   cert_bytes.length   // entry length
    write bytes   cert_bytes          // entry body
write bytes   aggregate_signature     // no length prefix (known size)
```

## CapBACInvocation

```
+--------+--------+----------------+---------------------------+-----+---------------------+----------------------+
| type   | scheme | chain_count    | certificate[0..n-1]       | ... | invocation          | aggregate_signature  |
| 1 byte | 1 byte | int32 (4 bytes)| (length-prefixed entries) |     | (length-prefixed)   | (scheme-dependent)   |
+--------+--------+----------------+---------------------------+-----+---------------------+----------------------+
```

### Layout

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | `type` | `0x02` (invocation) |
| 1 | 1 | `scheme_id` | BLS scheme identifier (`0x01` or `0x02`) |
| 2 | 4 | `chain_count` | Number of certificates in the chain |
| 6 | variable | `certificates` | `chain_count` length-prefixed certificate entries |
| ... | 4 + variable | `invocation` | Length-prefixed invocation body |
| ... | 48 or 96 | `aggregate_signature` | BLS aggregate signature (size depends on scheme) |

The only structural difference from `CapBACCertificate` is the length-prefixed invocation body inserted between the certificate chain and the aggregate signature.

### Pseudocode

```
write byte    0x02                         // type tag
write byte    scheme.id                    // scheme
write int32   certificates.length          // chain count
for each certificate:
    cert_bytes = certificate.toBytes()
    write int32   cert_bytes.length        // entry length
    write bytes   cert_bytes               // entry body
invocation_bytes = invocation.toBytes()
write int32   invocation_bytes.length      // invocation length
write bytes   invocation_bytes             // invocation body
write bytes   aggregate_signature          // no length prefix (known size)
```

## Certificate

A single certificate in the delegation chain. This is the body of each length-prefixed entry in the chain.

```
+--------------+---------+--------------+---------+----------+--------------+------------+
| issuer_len   | issuer  | subject_len  | subject | expiry   | cap_len      | capability |
| int32        | (bytes) | int32        | (bytes) | int64    | int32        | (bytes)    |
+--------------+---------+--------------+---------+----------+--------------+------------+
```

| Size | Field | Description |
|------|-------|-------------|
| 4 | `issuer_length` | Length of issuer PrincipalId |
| variable | `issuer` | Issuer's public key bytes (48 or 96 bytes depending on scheme) |
| 4 | `subject_length` | Length of subject PrincipalId |
| variable | `subject` | Subject's public key bytes |
| 8 | `expiration` | Unix epoch seconds (int64, big-endian) |
| 4 | `capability_length` | Length of capability payload |
| variable | `capability` | Opaque capability bytes (application-defined encoding) |

The issuer and subject are `PrincipalId` values, which are raw BLS public key bytes. Their length will be 48 bytes under `MIN_PK` or 96 bytes under `MIN_SIG`.

## Invocation

The invocation body. Same structure as a Certificate but with `invoker` instead of `issuer`/`subject`, and no subject field (the invoker is the terminal actor in the chain).

```
+--------------+----------+----------+--------------+------------+
| invoker_len  | invoker  | expiry   | cap_len      | capability |
| int32        | (bytes)  | int64    | int32        | (bytes)    |
+--------------+----------+----------+--------------+------------+
```

| Size | Field | Description |
|------|-------|-------------|
| 4 | `invoker_length` | Length of invoker PrincipalId |
| variable | `invoker` | Invoker's public key bytes |
| 8 | `expiration` | Unix epoch seconds (int64, big-endian) |
| 4 | `capability_length` | Length of capability payload |
| variable | `capability` | Opaque capability bytes (application-defined encoding) |

## Aggregate Signature

The aggregate signature is always the **last field** in the token. It is written without a length prefix because the size is determined by the scheme:

- `MIN_PK` (`0x01`): signatures live in G2, so **96 bytes**
- `MIN_SIG` (`0x02`): signatures live in G1, so **48 bytes**

The aggregate signature covers:

- **Certificate token:** one signature per certificate, each over that certificate's `toBytes()`, aggregated together
- **Invocation token:** all certificate signatures plus the invoker's signature over the invocation's `toBytes()`

During verification, the verifier reconstructs the list of (public key, message) pairs from the chain and invocation, then calls `aggregateVerify` once.

## Validation on Deserialization

The `fromBytesPayload` methods enforce:

1. All `int32` length values must be non-negative and not exceed `dis.available()`
2. After reading all fields, `dis.available()` must be 0 (no trailing bytes)

Violation of either rule throws `IOException`.

## Worked Example

A `MIN_PK` invocation token with a 2-certificate chain, 5-byte capability per cert, and 5-byte invocation capability:

```
Offset  Bytes         Field
------  -----         -----
0       01            type = CERTIFICATE? No: 02 = INVOCATION
0       02            type = INVOCATION
1       01            scheme = MIN_PK
2-5     00 00 00 02   chain_count = 2

                      --- certificate[0] ---
6-9     00 00 00 45   cert_length = 69 (4+48 + 4+48 + 8 + 4+5 = 121? let's recalc)
```

For a concrete size calculation with `MIN_PK` (48-byte public keys):

```
Certificate bytes = 4 + 48 (issuer) + 4 + 48 (subject) + 8 (expiry) + 4 + N (capability)
                  = 116 + N

Invocation bytes  = 4 + 48 (invoker) + 8 (expiry) + 4 + N (capability)
                  = 64 + N
```

Total token size for a 2-cert chain with 5-byte capabilities and a 5-byte invocation capability:

```
  1                        type tag
+ 1                        scheme id
+ 4                        chain_count
+ 2 * (4 + 121)            2 certificates, each 4-byte prefix + (116 + 5) body
+ (4 + 69)                 invocation, 4-byte prefix + (64 + 5) body
+ 96                       aggregate signature (MIN_PK)
---------
= 1 + 1 + 4 + 250 + 73 + 96
= 425 bytes
```

The same token under `MIN_SIG` (96-byte public keys, 48-byte signatures):

```
Certificate bytes = 4 + 96 + 4 + 96 + 8 + 4 + 5 = 217
Invocation bytes  = 4 + 96 + 8 + 4 + 5          = 117

Total = 1 + 1 + 4 + 2*(4 + 217) + (4 + 117) + 48
      = 1 + 1 + 4 + 442 + 121 + 48
      = 617 bytes
```
