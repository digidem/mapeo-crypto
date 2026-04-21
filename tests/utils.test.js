// @ts-check
import test from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes, createHash } from 'node:crypto'
import {
  KeyManager,
  sign,
  verifySignature,
  keyToPublicId,
  keyToInviteId,
} from '../index.js'
import z32 from 'z32'

test('sign & verify', () => {
  const km = new KeyManager(randomBytes(16))
  const keyPair = km.getIdentityKeypair()
  const message = Buffer.from('hello world')

  const sig = sign(message, keyPair.secretKey)

  assert.equal(sig.length, 64)
  assert.ok(verifySignature(message, sig, keyPair.publicKey))
  assert.ok(!verifySignature(message, Buffer.alloc(64), keyPair.publicKey))
})

test('key to public ID', () => {
  const key = createHash('sha256').update('test key').digest()
  const publicId = keyToPublicId(key)
  assert.equal(
    publicId,
    'zmpu4uwx5eze9jmug6ycgwnirsy4rzfym3c4987gpjsdxzmomi4o',
    'checks for consistency - a change is a breaking change'
  )
  assert.equal(keyToPublicId(key), publicId, 'deterministic')
  assert.notDeepEqual(
    z32.decode(publicId),
    key,
    "didn't do something dumb and encode without hashing"
  )
})

test('key to invite ID', () => {
  const key = createHash('sha256').update('test key').digest()
  const inviteId = keyToInviteId(key)
  assert.deepEqual(
    inviteId,
    Buffer.from('eQro+t0dzx2AFf3h9Bh5A94i0YdR19xJkq+NGny+IS0=', 'base64'),
    'checks for consistency - a change is a breaking change'
  )
  assert.deepEqual(keyToInviteId(key), inviteId, 'deterministic')
  assert.notDeepEqual(
    key,
    inviteId,
    "didn't do something dumb and encode without hashing"
  )
})
