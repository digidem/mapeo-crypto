// @ts-check
const { test } = require('tap')
const crypto = require('crypto')
const sodium = require('sodium-native')
const {
  deriveNamedKey: derive,
  deriveMasterKeyFromRootKey: deriveMasterKey,
  signKeypair,
  boxKeypair,
  validateSignKeypair,
  validateBoxKeypair,
} = require('./key-utils')

test('deriveNamedKey', (t) => {
  t.test('can derive', function (t) {
    const mk = Buffer.alloc(32)
    const TOKEN1 = Buffer.alloc(32, 1)
    const TOKEN2 = Buffer.alloc(32, 2)

    t.same(derive(mk, 'a'), derive(mk, 'a'))
    t.same(derive(mk, 'a', TOKEN1), derive(mk, 'a', TOKEN1))
    t.notSame(derive(mk, 'a'), derive(mk, 'a', TOKEN1))
    t.notSame(derive(mk, 'b', TOKEN1), derive(mk, 'a', TOKEN1))
    t.notSame(derive(mk, 'a', TOKEN2), derive(mk, 'a', TOKEN1))

    t.end()
  })
  t.end()
})

test('deriveMasterKeyFromRootKey', (t) => {
  t.test('can derive', function (t) {
    const identity1 = Buffer.from('15c1d5fd40f4f35eb1877e65febf94ac', 'hex')
    const identity2 = Buffer.from('15c1d5fd40f4f35eb1877e65febf94ad', 'hex')

    t.same(deriveMasterKey(identity1), deriveMasterKey(identity1))
    t.notSame(deriveMasterKey(identity1), deriveMasterKey(identity2))

    t.end()
  })
  t.end()
})

test('signKeypair(seed) generates deterministic keys', (t) => {
  const seed = crypto.randomBytes(32)
  t.same(signKeypair(seed), signKeypair(seed))
  t.end()
})

test('signKeypair() does not generate deterministic keys', (t) => {
  t.notSame(signKeypair(), signKeypair())
  t.end()
})

test('signKeypair() generates valid keys', (t) => {
  t.ok(validateSignKeypair(signKeypair()))
  t.ok(validateSignKeypair(signKeypair(crypto.randomBytes(32))))
  t.end()
})

test('boxKeypair() generates valid keys', (t) => {
  t.ok(validateBoxKeypair(boxKeypair()))
  t.end()
})
