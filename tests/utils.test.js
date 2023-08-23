// @ts-check
const { test } = require('tap')
const { randomBytes } = require('crypto')
const { KeyManager, sign, verifySignature } = require('../')

test('sign & verify', function (t) {
  const km = new KeyManager(randomBytes(16))
  const keyPair = km.getIdentityKeypair()
  const message = Buffer.from('hello world')

  const sig = sign(message, keyPair.secretKey)

  t.equal(sig.length, 64)
  t.ok(verifySignature(message, sig, keyPair.publicKey))
  t.notOk(verifySignature(message, Buffer.alloc(64), keyPair.publicKey))
  t.end()
})
