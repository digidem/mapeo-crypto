## @mapeo/crypto

[![Node.js CI](https://github.com/digidem/mapeo-crypto/workflows/Node.js%20CI/badge.svg)](https://github.com/digidem/mapeo-crypto/actions/workflows/node.js.yml)
[![Coverage Status](https://coveralls.io/repos/github/digidem/mapeo-crypto/badge.svg)](https://coveralls.io/github/digidem/mapeo-crypto)
[![Npm package version](https://img.shields.io/npm/v/@mapeo/crypto)](https://npmjs.com/package/@mapeo/crypto)

Key management and encryption / decryption functions for Mapeo.

## Table of Contents

  - [KeyManager](#keymanager)
      - [Parameters](#parameters)
    - [`km.getIdentityKeypair()`](#kmgetidentitykeypair)
    - [`km.getIdentityBackupCode()`](#kmgetidentitybackupcode)
    - [`km.getHypercoreKeypair(name, namespace)`](#kmgethypercorekeypairname-namespace)
      - [Parameters](#parameters-1)
    - [`KeyManager.generateRootKey()`](#keymanagergeneraterootkey)
    - [`KeyManager.decodeBackupCode(backupCode)`](#keymanagerdecodebackupcodebackupcode)
      - [Parameters](#parameters-2)
  - [Project Invites](#project-invites)
    - [`invites.encodeJoinRequest(joinRequest, options)`](#invitesencodejoinrequestjoinrequest-options)
      - [Parameters](#parameters-3)
    - [`invites.decodeJoinRequest(str, options)`](#invitesdecodejoinrequeststr-options)
      - [Parameters](#parameters-4)
    - [`invites.generateInvite(joinRequest, options)`](#invitesgenerateinvitejoinrequest-options)
      - [Parameters](#parameters-5)
    - [`invites.decodeInviteSecretMessage(invite, identityPublicKey, identitySecretKey, options)`](#invitesdecodeinvitesecretmessageinvite-identitypublickey-identitysecretkey-options)
      - [Parameters](#parameters-6)
  - [Type `JoinRequest`](#type-joinrequest)

## API

### KeyManager

```js
const { KeyManager } = require('@mapeo/crypto')

const km = new KeyManager(rootKey)
```

The KeyManager class derives the key pairs used for identifying the device
and for all the hypercores on the device. All the key pairs are generated
deterministically from a single 16-byte root key. The backup code can be
used to backup this identity and recover it on a new device. The root key
and backup code must be kept secret at all times - someone who has this key
can impersonate the user to another Mapeo user.

##### Parameters

- `rootKey: Buffer` 16-bytes of random data that uniquely identify the device, used to derive a 32-byte master key, which is used to derive all the keypairs used for Mapeo

#### `km.getIdentityKeypair()`

Generate a deterministic ed25519 signing keypair that uniquely identifies
this device. Used for identifying the device on the network to other peers.

Returns `{ publicKey: Buffer, secretKey: Buffer }`

#### `km.getIdentityBackupCode()`

Generate a backup code for the `rootKey`. The backup code will be a
30-character string, starting with the letter `M`. It encodes the root key
and can be used to recover the root key on another device. It should be
treated as a secure password: someone with access to a backup code can
impersonate the identity of the holder.

Returns `string`

#### `km.getHypercoreKeypair(name, namespace)`

Generate a deterministic signing keypair for a given project key and name.
API compatible with Corestore-next.

##### Parameters

- `name: string` Local name for the keypair
- `namespace: Buffer` 32-byte namespace

Returns `{ publicKey: Buffer, secretKey: Buffer }`

#### `KeyManager.generateRootKey()`

Static method to generate a new random root key. This is used to derive a
master key: all keys are deterministically derived from this root key, so
this should only be used once on each device and the key should be securely
stored.

Returns 16-byte `Buffer` of random data

#### `KeyManager.decodeBackupCode(backupCode)`

Static method to decode a root key from a backup code. Throws an error if
the CRC check fails.

##### Parameters

- `backupCode: string` 30-character base32 encoded backup code

Returns `Buffer` The 16-byte root key encoded in the backup code

### Project Invites

```js
const { invites } = require('@mapeo/crypto`)
```

Functions for generating project join requests and responding with an encrypted
invite.

#### `invites.encodeJoinRequest(joinRequest, options)`

Encode a join request encoded to a string for use in a QR code or a URL. A
join request includes (unencrypted) the identity public key of the device
sending the join request. The optional `name` is used to give context to the
receiver of the join request. It is unencrypted, so the user should not
reveal secret information in this field, or should ensure that the join
request is sent via a secure channel.

`base32` is used for a QR code because it enables alphanumeric encoding
(uppercase A-Z, 0-9) which is more compact. `base62` is used for URLs, rather
than `base64`, because symbols like `+` can break URL parsing (e.g. in an SMS
message, only part of a URL before a `+` might be clickable).

##### Parameters

- `joinRequest` **JoinRequest** A join request message
- `options: object`

  - `options.encoding: 'base32' | 'base62'` Use base32 if using for an alphanumeric encoded QR Code (uppercase A-Z, 0-9), or base62 for a URL.

Returns `string` Encoded join request

#### `invites.decodeJoinRequest(str, options)`

Decode a join request from a string-encoded join request. Will throw if the
string does not encode a valid join request message.

##### Parameters

- `str: string` Join request encoded as a string
- `options: object`

  - `options.encoding: 'base32' | 'base62'` Use base32 if using for an alphanumeric encoded QR Code (uppercase A-Z, 0-9), or base62 for a URL.

Returns **JoinRequest** Decoded join request

#### `invites.generateInvite(joinRequest, options)`

Generate an encrypted invite encoded as a string for use in a QR code or a
URL. Invites are encrypted and can only be decrypted by the owner of the
private key associated with the identity public key sent in the join request.

`base32` is used for a QR code because it enables alphanumeric encoding
(uppercase A-Z, 0-9) which is more compact. `base62` is used for URLs, rather
than `base64`, because symbols like `+` can break URL parsing (e.g. in an SMS
message, only part of a URL before a `+` might be clickable).

##### Parameters

- `joinRequest: JoinRequest`
- `options`
  - `options.encoding: 'base32' | 'base62'` Use base32 if using for an alphanumeric encoded QR Code (uppercase A-Z, 0-9), or base62 for a URL.
  - `options.projectKey: Buffer` Project key for project you wish to generate the invite for
  - `[options.encryptionKey: Buffer]` Optional encryption key, used for on-disk encryption/decryption of an encrypted project.

Returns `string` Encoded invite

#### `invites.decodeInviteSecretMessage(invite, identityPublicKey, identitySecretKey, options)`

Decode and decrypt an invite secret message from a string-encoded invite. The
decrypted message includes the project key for the project the invite is for.

##### Parameters

- `invite: string` Invite encoded as a string
- `identityPublicKey: Buffer` 32-byte signing public key for the device receiving the invite
- `identitySecretKey: Buffer` 32-byte signing secret key for the device receiving the invite
- `options`

  - `options.encoding: 'base32' | 'base62'` Use base32 if using for an alphanumeric encoded QR Code (uppercase A-Z, 0-9), or base62 for a URL.

Returns `{ projectKey: Buffer, encryptionKey?: Buffer }` Decrypted secret project key and optional encryption key.

### Type `JoinRequest`

```typescript
{
    identityPublicKey: Buffer,
    host?: { host: string, port: number },
    name?: string
}
```