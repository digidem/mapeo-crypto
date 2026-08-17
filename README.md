## @comapeo/crypto

[![Node.js CI](https://github.com/digidem/comapeo-crypto/workflows/Node.js%20CI/badge.svg)](https://github.com/digidem/comapeo-crypto/actions/workflows/node.js.yml)
[![Npm package version](https://img.shields.io/npm/v/@comapeo/crypto)](https://npmjs.com/package/@comapeo/crypto)

Key management and encryption / decryption functions for Mapeo.

## API

<!-- This API documentation is maintained by hand. Please keep it in sync when changing the source. -->

Anything that takes key material accepts any `Uint8Array`, so a key read
straight off a native bridge needs no conversion. Everything returned is a
Node `Buffer`.

#### Table of Contents

*   [sign](#sign)
    *   [Parameters](#parameters)
*   [verifySignature](#verifysignature)
    *   [Parameters](#parameters-1)
*   [keyToPublicId](#keytopublicid)
    *   [Parameters](#parameters-2)
*   [KeyManager](#keymanager)
    *   [Parameters](#parameters-3)
    *   [getMasterKey](#getmasterkey)
    *   [getIdentityKeypair](#getidentitykeypair)
    *   [deriveSwarmIdentity](#deriveswarmidentity)
        *   [Parameters](#parameters-4)
    *   [getIdentityBackupCode](#getidentitybackupcode)
    *   [getHypercoreKeypair](#gethypercorekeypair)
        *   [Parameters](#parameters-5)
    *   [getDerivedKey](#getderivedkey)
        *   [Parameters](#parameters-6)
    *   [decryptLocalMessage](#decryptlocalmessage)
        *   [Parameters](#parameters-7)
    *   [encryptLocalMessage](#encryptlocalmessage)
        *   [Parameters](#parameters-8)
    *   [generateRootKey](#generaterootkey)
    *   [generateProjectKeypair](#generateprojectkeypair)
    *   [decodeBackupCode](#decodebackupcode)
        *   [Parameters](#parameters-9)
*   [Keypair](#keypair)
*   [deriveMasterKeyFromRootKey](#derivemasterkeyfromrootkey)
    *   [Parameters](#parameters-10)
*   [deriveNamedKey](#derivenamedkey)
    *   [Parameters](#parameters-11)
*   [validateSignKeypair](#validatesignkeypair)
    *   [Parameters](#parameters-12)

### sign

Sign message using secretKey

#### Parameters

*   `message` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)**&#x20;
*   `secretKey` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)**&#x20;

Returns **[Buffer](https://nodejs.org/api/buffer.html)** 64-byte detached signature

### verifySignature

Verify if the message signature is valid

#### Parameters

*   `message` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)**&#x20;
*   `signature` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)**&#x20;
*   `publicKey` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)** public key of keypair used to sign message

Returns **[boolean](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Boolean)**&#x20;

### keyToPublicId

Get a public ID from a key. The public ID is a hash
of the key and safe to share publicly. The hash is encoded as
[z-base-32](http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt)

#### Parameters

*   `key` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)**&#x20;

Returns **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** z-base-32 encoded hash of the key

### KeyManager

The KeyManager class derives the key pairs used for identifying the device
and for all the hypercores on the device. All the key pairs are generated
deterministically from a single 16-byte root key. The backup code can be
used to backup this identity and recover it on a new device. The root key
and backup code must be kept secret at all times - someone who has this key
can impersonate the user to another CoMapeo user.

Key material passed to the constructor is copied into the instance's own
locked memory, so the caller is free to zero its buffers afterwards.

#### Parameters

*   `rootKey` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)** 16-bytes of random data that uniquely identify the device, used to derive a 32-byte master key, which is used to derive all the keypairs used for CoMapeo
*   `opts` **[object](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Object)?**&#x20;

    *   `opts.masterKey` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)?** Previously derived 32-byte master key for this same `rootKey`, e.g. read from a cache. When provided the expensive derivation is skipped and this value is used directly. The caller is responsible for it actually being `deriveMasterKeyFromRootKey(rootKey)`: the pairing is trusted, not verified, because verifying it would mean running the derivation this option exists to avoid. A mismatched pair yields a working but *different* identity, whose backup code still encodes `rootKey`.

#### getMasterKey

The 32-byte master key from which every other key is derived. Returns a
copy, so the caller can zero it without touching the instance's secure
buffer.

Returns **[Buffer](https://nodejs.org/api/buffer.html)**&#x20;

#### getIdentityKeypair

Generate a deterministic ed25519 signing keypair that uniquely identifies
this device. Used for identifying the device on the network to other peers.

Returns **[Keypair](#keypair)**&#x20;

#### deriveSwarmIdentity

Generate a deterministic ed25519 signing keypair that uniquely identifies
this device for the day. Used for identifying the device on hyperswarm.
Keys change every day to make it harder to track a specific device.
Keys persist accross app restarts.

##### Parameters

*   `date` **[Date](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Date)?**  (optional, default `new Date()`)

Returns **[Keypair](#keypair)**&#x20;

#### getIdentityBackupCode

The backup code for this device's identity: a string-encoded form of the
root key, for the user to write down. Depends only on the root key, so it
is unaffected by a `masterKey` passed to the constructor.

Returns **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** 30-character backup code

#### getHypercoreKeypair

Generate a deterministic signing keypair for a given project key and name.
API compatible with Corestore-next.

##### Parameters

*   `name` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** Local name for the keypair
*   `namespace` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)** 32-byte namespace

Returns **[Keypair](#keypair)**&#x20;

#### getDerivedKey

Generate a derived key for the given name. Deterministic: the same
key will be generated for the same name if the identity key is the
same.

##### Parameters

*   `name` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)**&#x20;
*   `token` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)?** Optional 32-byte token to use for key derivation, e.g. to namespace keys.

Returns **[Buffer](https://nodejs.org/api/buffer.html)** 32-byte buffer

#### decryptLocalMessage

Decrypt an encrypted message using the provided nonce parameter

##### Parameters

*   `cyphertext` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)**&#x20;
*   `nonce` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)** 24-byte nonce

#### encryptLocalMessage

Encrypt a message using the provided nonce parameter
This should only be used for encrypting local messages, not for sending
messages over the internet, because the nonce is non-random, so messages
could be subject to replay attacks

##### Parameters

*   `msg` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)**&#x20;
*   `nonce` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)** 24-byte nonce

#### generateRootKey

Generate a new random identity key. This is used to derive a master key:
all keys are deterministically derived from this identity key, so this
should only be used once on each device and the key should be securely
stored.

Returns **[Buffer](https://nodejs.org/api/buffer.html)**&#x20;

#### generateProjectKeypair

Generate a keypair for a new project. The public key of this keypair
becomes the project key. The keypair should be used as the keypair for the
hypercore in the 'auth' namespace for the project creator.

This keypair is non-deterministic, it must be persisted somewhere.

#### decodeBackupCode

Decode the root key from a backup code. Throws an error if the CRC
check fails.

Input is normalized before validation, because backup codes are
transcribed by hand: case is ignored, and whitespace and hyphens (which
users add to group the code for legibility) are stripped. The base32
alphabet is Crockford's, so `O` reads as `0` and `I`/`L` as `1`.

##### Parameters

*   `stringEncodedBackupCode` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)**&#x20;

Returns **[Buffer](https://nodejs.org/api/buffer.html)** The 16-byte root key encoded in the backup code

### Keypair

Type: {publicKey: [Buffer](https://nodejs.org/api/buffer.html), secretKey: [Buffer](https://nodejs.org/api/buffer.html)}

### deriveMasterKeyFromRootKey

Derive a 32-byte master key from the 16-byte root key. We compromise
entropy (16 bytes vs 32) for the sake of an root key that can be easily
written down (as 30 base-32 characters or 44 numerical digits). A 32-byte key
would be too long and more prone to error when transcribing. We could just
hash the root key, in the same way that derive-key hashes values, but by
using pwhash we increase security since it's more work to brute force how the
16-bytes of entropy of the root key map to the 32-bytes of entropy of the
master key.

#### Parameters

*   `rootKey` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)** 16-bytes root key

Returns **[Buffer](https://nodejs.org/api/buffer.html)** 32-byte master key

### deriveNamedKey

Derive a named key from a 32 byte high-entropy master key. This can be
32-bytes of cryptographically secure randomness, eg from a CSPRNG. Do NOT use
low entropy soruces such a passwords, passphrases or randomness from a
predictable RNG.

Adapted from <https://github.com/hyperdivision/derive-key/tree/v1.0.1> and the
implementation in corestore-next

#### Parameters

*   `masterKey` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)** 32-byte high-entropy master key
*   `keyName` **[string](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String)** Name of the key to derive
*   `token` **[Uint8Array](https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)?** Optional token (32 bytes) to use for key derivation, e.g. for namespacing keys

Returns **[Buffer](https://nodejs.org/api/buffer.html)** 32-byte derived key

### validateSignKeypair

#### Parameters

*   `keypair` **[Keypair](#keypair)**&#x20;
