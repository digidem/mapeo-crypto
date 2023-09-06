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
  - [`km.getDerivedKey(name, namespace)`](#kmgetderivedkeyname-namespace)
    - [Parameters](#parameters-2)
  - [`km.decryptLocalMessage(cypherText, nonce)`](#kmdecryptlocalmessagecyphertext-projectid)
    - [Parameters](#parameters-3)
  - [`km.encryptLocalMessage(msg, nonce)`](#kmencryptlocalmessagemsg-projectid)
    - [Parameters](#parameters-4)
  - [`KeyManager.generateRootKey()`](#keymanagergeneraterootkey)
  - [`KeyManager.decodeBackupCode(backupCode)`](#keymanagerdecodebackupcodebackupcode)
    - [Parameters](#parameters-5)
  - [`KeyManager.generateProjectKeypair()`](#keymanagergenerateprojectkeypair)
- [`sign(message, secretKey)`](#signmessage-secretkey)
  - [Parameters](#parameters-10)
- [`verify(message, signature, publicKey)`](#verifymessage-signature-publickey)
  - [Parameters](#parameters-11)
- [`projectKeyToPublicId(projectKey)`](#projectkeytopublicidprojectkey)
  - [Parameters](#parameters-12)
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

#### `km.getDerivedKey(name, namespace)`

Generate a derived key for the given name. Deterministic: the same key will be
generated for the same name if the identity key is the same.

##### Parameters

- `name: string` Local name for the key
- `namespace: Buffer` 32-byte namespace

Returns 32-byte `Buffer`

#### `km.decryptLocalMessage(cypherText, projectId)`

Decrypt an encrypted message using the provided nonce parameter

##### Parameters

- `cyphertext: Buffer` Encrypted message to decrypt
- `nonce: Buffer` 24-byte nonce

#### `km.encryptLocalMessage(msg, nonce)`

Encrypt a message using the provided nonce parameter
This should only be used for encrypting local messages, not for sending
messages over the internet, because the nonce is non-random, so messages
could be subject to replay attacks.

##### Parameters

- `msg: Buffer` Message to encrypt
- `nonce: Buffer` 24-byte nonce

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

#### `KeyManager.generateProjectKeypair()`

Generate a keypair for a new project. The public key of this keypair becomes the project key. The keypair should be used as the keypair for the hypercore in the 'auth' namespace for the project creator.

This keypair is non-deterministic, it must be persisted somewhere.

Returns `{ publicKey: Buffer, secretKey: Buffer }`

### `sign(message, secretKey)`

Sign `message` using `secretKey`

#### Parameters

- `message: Buffer`
- `secretKey: Buffer`

Returns `Buffer` signature of the message

### `verify(message, signature, publicKey)`

Verify that `signature` is a valid signature of `message` created by the owner of `publicKey`.

#### Parameters

- `message: Buffer`
- `signature: Buffer`
- `publicKey: Buffer`

Returns `boolean` indicating if valid or not.

### `projectKeyToPublicId(projectKey)`

Get a project public ID from the project key. The project public ID is a hash of the project key and safe to share publicly. The hash is encoded as [z-base-32](http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt)

#### Parameters

- `projectKey: Buffer`

Returns `string` z-base-32 encoded hash of the project key

### Type `JoinRequest`

```typescript
{
    identityPublicKey: Buffer,
    host?: { host: string, port: number },
    name?: string
}
```
