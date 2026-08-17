import test from 'node:test'
import assert from 'node:assert/strict'
import * as comapeoCrypto from '../src/index.js'
import KeyManager from '../src/key-manager.js'
import { deriveMasterKeyFromRootKey } from '../src/lib/key-utils.js'
import { DEVICE_A, u8 } from './fixtures.js'

const MESSAGE = Buffer.from('hello world')

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
  const km = new comapeoCrypto.KeyManager(u8(DEVICE_A.rootKey), {
    masterKey: u8(DEVICE_A.masterKey),
  })
  /** @type {import('../src/lib/key-utils.js').Keypair} */
  const keypair = km.getIdentityKeypair()
  /** @type {Buffer} */
  const signature = comapeoCrypto.sign(u8(MESSAGE), u8(keypair.secretKey))
  /** @type {boolean} */
  const isValid = comapeoCrypto.verifySignature(
    u8(MESSAGE),
    u8(signature),
    u8(keypair.publicKey),
  )
  /** @type {string} */
  const publicId = comapeoCrypto.keyToPublicId(u8(keypair.publicKey))

  assert.ok(isValid)
  assert.equal(typeof publicId, 'string')
})

// Inputs widened to Uint8Array; returns did not. comapeo-core calls Buffer
// methods on all of these.
test('everything handed back is a Buffer', () => {
  const km = new comapeoCrypto.KeyManager(u8(DEVICE_A.rootKey), {
    masterKey: u8(DEVICE_A.masterKey),
  })
  const keypair = km.getIdentityKeypair()

  for (const [label, value] of Object.entries({
    getMasterKey: km.getMasterKey(),
    getDerivedKey: km.getDerivedKey('a', new Uint8Array(32).fill(1)),
    'keypair.publicKey': keypair.publicKey,
    'keypair.secretKey': keypair.secretKey,
    encryptLocalMessage: km.encryptLocalMessage(
      u8(MESSAGE),
      new Uint8Array(24).fill(7),
    ),
    generateRootKey: KeyManager.generateRootKey(),
    decodeBackupCode: KeyManager.decodeBackupCode(DEVICE_A.backupCode),
    sign: comapeoCrypto.sign(u8(MESSAGE), u8(keypair.secretKey)),
    deriveMasterKeyFromRootKey: deriveMasterKeyFromRootKey(
      u8(DEVICE_A.rootKey),
    ),
  })) {
    assert.ok(Buffer.isBuffer(value), label)
  }
})
