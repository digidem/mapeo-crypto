import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'crypto'
import {
  deriveNamedKey as derive,
  deriveMasterKeyFromRootKey as deriveMasterKey,
  signKeypair,
  validateSignKeypair,
} from '../src/lib/key-utils.js'
import { DEVICE_A, DEVICE_B } from './fixtures.js'

// Locks the Argon2id output forever: any drift here is fleet-wide identity
// loss. Two vectors, so this covers determinism and distinctness too - which is
// why no separate test derives the same key twice just to compare.
test('pinned master key derivation vectors', () => {
  for (const { rootKey, masterKey } of [DEVICE_A, DEVICE_B]) {
    assert.deepEqual(Buffer.from(deriveMasterKey(rootKey)), masterKey)
  }
})

test('deriveMasterKeyFromRootKey rejects keys that are not 16 bytes', () => {
  for (const length of [0, 15, 17, 32]) {
    assert.throws(
      () => deriveMasterKey(Buffer.alloc(length)),
      /rootKey must be 16 bytes/,
      `length ${length}`,
    )
  }
})

test('deriveNamedKey', () => {
  const mk = Buffer.alloc(32)
  const TOKEN1 = Buffer.alloc(32, 1)
  const TOKEN2 = Buffer.alloc(32, 2)

  assert.deepEqual(derive(mk, 'a'), derive(mk, 'a'))
  assert.deepEqual(derive(mk, 'a', TOKEN1), derive(mk, 'a', TOKEN1))
  assert.notDeepEqual(derive(mk, 'a'), derive(mk, 'a', TOKEN1))
  assert.notDeepEqual(derive(mk, 'b', TOKEN1), derive(mk, 'a', TOKEN1))
  assert.notDeepEqual(derive(mk, 'a', TOKEN2), derive(mk, 'a', TOKEN1))
})

test('deriveNamedKey rejects low-entropy inputs', () => {
  assert.throws(() => derive(Buffer.alloc(31), 'a'), /masterKey must be/)
  assert.throws(
    () => derive(Buffer.alloc(32), 'a', Buffer.alloc(31)),
    /token must be/,
  )
})

test('signKeypair(seed) generates deterministic keys', () => {
  const seed = crypto.randomBytes(32)
  assert.deepEqual(signKeypair(seed), signKeypair(seed))
})

test('signKeypair() does not generate deterministic keys', () => {
  assert.notDeepEqual(signKeypair(), signKeypair())
})

test('signKeypair() generates valid keys', () => {
  assert.ok(validateSignKeypair(signKeypair()))
  assert.ok(validateSignKeypair(signKeypair(crypto.randomBytes(32))))
})

test('signKeypair rejects a short seed', () => {
  assert.throws(() => signKeypair(Buffer.alloc(31)), /seed must be/)
})
