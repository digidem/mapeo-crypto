import test from 'node:test'
import assert from 'node:assert/strict'
import * as comapeoCrypto from '../src/index.js'
import KeyManager from '../src/key-manager.js'
import { deriveMasterKeyFromRootKey } from '../src/lib/key-utils.js'
import { DEVICE_A } from './fixtures.js'

// Every other test reaches into src/ directly, so without this nothing checks
// that the entry point still exposes them.
test('public export surface', () => {
  assert.deepEqual(Object.keys(comapeoCrypto), [
    'KeyManager',
    'deriveMasterKeyFromRootKey',
    'keyToPublicId',
    'sign',
    'verifySignature',
  ])
  assert.equal(comapeoCrypto.KeyManager, KeyManager)
  assert.equal(
    comapeoCrypto.deriveMasterKeyFromRootKey,
    deriveMasterKeyFromRootKey,
  )
})

// The annotations are the test: `npm run type` type-checks this file, so a
// signature that stops matching what the README documents fails the build.
test('exports match their documented types', () => {
  const km = new comapeoCrypto.KeyManager(DEVICE_A.rootKey, {
    masterKey: DEVICE_A.masterKey,
  })
  /** @type {import('../src/lib/key-utils.js').Keypair} */
  const keypair = km.getIdentityKeypair()
  /** @type {Buffer} */
  const signature = comapeoCrypto.sign(
    Buffer.from('hello world'),
    keypair.secretKey,
  )
  /** @type {boolean} */
  const isValid = comapeoCrypto.verifySignature(
    Buffer.from('hello world'),
    signature,
    keypair.publicKey,
  )
  /** @type {string} */
  const publicId = comapeoCrypto.keyToPublicId(keypair.publicKey)

  assert.ok(isValid)
  assert.equal(typeof publicId, 'string')
})
