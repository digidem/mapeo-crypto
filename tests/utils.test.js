import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { sign, verifySignature, keyToPublicId } from '../src/index.js'
import z32 from 'z32'
import { DEVICE_A, DEVICE_B, keyManagerFor } from './fixtures.js'

test('sign & verify', () => {
  const keyPair = keyManagerFor(DEVICE_A).getIdentityKeypair()
  const message = Buffer.from('hello world')

  const sig = sign(message, keyPair.secretKey)

  assert.equal(sig.length, 64)
  assert.ok(verifySignature(message, sig, keyPair.publicKey))
})

// CoreOwnership records carry signatures straight off the wire, and treat a
// false return as "this peer does not own that core". Each of these has to come
// back false rather than throw or, worse, pass.
test('verifySignature rejects everything it should', () => {
  const keyPair = keyManagerFor(DEVICE_A).getIdentityKeypair()
  const otherKeyPair = keyManagerFor(DEVICE_B).getIdentityKeypair()
  const message = Buffer.from('hello world')
  const sig = sign(message, keyPair.secretKey)

  const tampered = Buffer.from(sig)
  tampered[0] ^= 1

  assert.ok(
    !verifySignature(message, Buffer.alloc(64), keyPair.publicKey),
    'an all-zero signature',
  )
  assert.ok(
    !verifySignature(message, tampered, keyPair.publicKey),
    'a tampered signature',
  )
  assert.ok(
    !verifySignature(Buffer.from('hello worlt'), sig, keyPair.publicKey),
    'a different message',
  )
  assert.ok(
    !verifySignature(message, sig, otherKeyPair.publicKey),
    'a different public key',
  )
})

test('key to public ID', () => {
  const key = createHash('sha256').update('test key').digest()
  const publicId = keyToPublicId(key)
  assert.equal(
    publicId,
    'zmpu4uwx5eze9jmug6ycgwnirsy4rzfym3c4987gpjsdxzmomi4o',
    'checks for consistency - a change is a breaking change',
  )
  assert.equal(keyToPublicId(key), publicId, 'deterministic')
  assert.notEqual(
    keyToPublicId(createHash('sha256').update('other key').digest()),
    publicId,
    'distinct keys get distinct IDs',
  )
  assert.notDeepEqual(
    z32.decode(publicId),
    key,
    "didn't do something dumb and encode without hashing",
  )
})
