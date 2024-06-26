// @ts-check
const { test } = require('tap')
const { randomBytes, createHash } = require('crypto')
const {
  KeyManager,
  sign,
  verifySignature,
  keyToPublicId,
  keyToInviteId,
} = require('../')
const z32 = require('z32')

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

test('key to public ID', function (t) {
  const key = createHash('sha256').update('test key').digest()
  const publicId = keyToPublicId(key)
  t.equal(
    publicId,
    'zmpu4uwx5eze9jmug6ycgwnirsy4rzfym3c4987gpjsdxzmomi4o',
    'checks for consistency - a change is a breaking change'
  )
  t.equal(keyToPublicId(key), publicId, 'deterministic')
  t.notSame(
    z32.decode(publicId),
    key,
    "didn't do something dumb and encode without hashing"
  )
  t.end()
})

test('key to invite ID', (t) => {
  const key = createHash('sha256').update('test key').digest()
  const inviteId = keyToInviteId(key)
  t.same(
    inviteId,
    Buffer.from('eQro+t0dzx2AFf3h9Bh5A94i0YdR19xJkq+NGny+IS0=', 'base64'),
    'checks for consistency - a change is a breaking change'
  )
  t.same(keyToInviteId(key), inviteId, 'deterministic')
  t.notSame(
    key,
    inviteId,
    "didn't do something dumb and encode without hashing"
  )
  t.end()
})
