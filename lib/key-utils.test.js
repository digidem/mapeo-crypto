import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'crypto'
import {
  deriveNamedKey as derive,
  deriveMasterKeyFromRootKey as deriveMasterKey,
  signKeypair,
  boxKeypair,
  validateSignKeypair,
  validateBoxKeypair,
} from './key-utils.js'

test('deriveNamedKey', (t) => {
  t.test('can derive', () => {
    const mk = Buffer.alloc(32)
    const TOKEN1 = Buffer.alloc(32, 1)
    const TOKEN2 = Buffer.alloc(32, 2)

    assert.deepEqual(derive(mk, 'a'), derive(mk, 'a'))
    assert.deepEqual(derive(mk, 'a', TOKEN1), derive(mk, 'a', TOKEN1))
    assert.notDeepEqual(derive(mk, 'a'), derive(mk, 'a', TOKEN1))
    assert.notDeepEqual(derive(mk, 'b', TOKEN1), derive(mk, 'a', TOKEN1))
    assert.notDeepEqual(derive(mk, 'a', TOKEN2), derive(mk, 'a', TOKEN1))
  })
})

test('deriveMasterKeyFromRootKey', (t) => {
  t.test('can derive', () => {
    const identity1 = Buffer.from('15c1d5fd40f4f35eb1877e65febf94ac', 'hex')
    const identity2 = Buffer.from('15c1d5fd40f4f35eb1877e65febf94ad', 'hex')

    assert.deepEqual(deriveMasterKey(identity1), deriveMasterKey(identity1))
    assert.notDeepEqual(deriveMasterKey(identity1), deriveMasterKey(identity2))
  })
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

test('boxKeypair() generates valid keys', () => {
  assert.ok(validateBoxKeypair(boxKeypair()))
})
