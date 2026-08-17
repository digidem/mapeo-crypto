import test from 'node:test'
import assert from 'node:assert/strict'
import KeyManager from '../src/key-manager.js'
import { sign, verifySignature, keyToPublicId } from '../src/index.js'
import {
  deriveMasterKeyFromRootKey,
  deriveNamedKey,
  signKeypair,
} from '../src/lib/key-utils.js'
import { DEVICE_A, keyManagerFor } from './fixtures.js'

/**
 * A plain Uint8Array over a copy of the same bytes - what a caller reading key
 * material off a native bridge or out of structured storage tends to hold.
 *
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
const u8 = (bytes) => Uint8Array.from(bytes)

const { rootKey, masterKey, backupCode } = DEVICE_A
const NAMESPACE = Buffer.alloc(32, 5)
const NONCE = Buffer.alloc(24, 7)
const MESSAGE = Buffer.from('hello world')

// The types say Uint8Array; these assert the runtime agrees. Buffer extends
// Uint8Array, so only the plain-Uint8Array direction needs proving.
test('KeyManager accepts Uint8Array inputs', () => {
  const fromBuffers = keyManagerFor(DEVICE_A)
  const fromU8 = new KeyManager(u8(rootKey), { masterKey: u8(masterKey) })

  assert.deepEqual(fromU8.getMasterKey(), fromBuffers.getMasterKey())
  assert.equal(fromU8.getIdentityBackupCode(), backupCode)
  assert.deepEqual(
    fromU8.getIdentityKeypair(),
    fromBuffers.getIdentityKeypair(),
  )
  assert.deepEqual(
    fromU8.getDerivedKey('a', u8(NAMESPACE)),
    fromBuffers.getDerivedKey('a', NAMESPACE),
  )
  assert.deepEqual(
    fromU8.getHypercoreKeypair('a', u8(NAMESPACE)),
    fromBuffers.getHypercoreKeypair('a', NAMESPACE),
  )

  const cyphertext = fromBuffers.encryptLocalMessage(MESSAGE, NONCE)
  assert.deepEqual(
    fromU8.encryptLocalMessage(u8(MESSAGE), u8(NONCE)),
    cyphertext,
  )
  assert.deepEqual(
    fromU8.decryptLocalMessage(u8(cyphertext), u8(NONCE)),
    MESSAGE,
  )
})

test('module functions accept Uint8Array inputs', () => {
  const keypair = keyManagerFor(DEVICE_A).getIdentityKeypair()
  const signature = sign(MESSAGE, keypair.secretKey)

  assert.deepEqual(sign(u8(MESSAGE), u8(keypair.secretKey)), signature)
  assert.ok(
    verifySignature(u8(MESSAGE), u8(signature), u8(keypair.publicKey)),
    'verifies',
  )
  assert.equal(
    keyToPublicId(u8(keypair.publicKey)),
    keyToPublicId(keypair.publicKey),
  )
  assert.deepEqual(
    Buffer.from(deriveMasterKeyFromRootKey(u8(rootKey))),
    masterKey,
  )
  assert.deepEqual(
    deriveNamedKey(u8(masterKey), 'a', u8(NAMESPACE)),
    deriveNamedKey(masterKey, 'a', NAMESPACE),
  )
  assert.deepEqual(signKeypair(u8(NAMESPACE)), signKeypair(NAMESPACE))
})

// Widening the inputs must not widen what comes back: comapeo-core calls
// Buffer methods (`.toString('hex')`, `.equals`) on all of these.
test('returns are still Buffers when given Uint8Array inputs', () => {
  const km = new KeyManager(u8(rootKey), { masterKey: u8(masterKey) })
  const keypair = km.getIdentityKeypair()

  for (const [label, value] of Object.entries({
    getMasterKey: km.getMasterKey(),
    getDerivedKey: km.getDerivedKey('a', u8(NAMESPACE)),
    'keypair.publicKey': keypair.publicKey,
    'keypair.secretKey': keypair.secretKey,
    encryptLocalMessage: km.encryptLocalMessage(u8(MESSAGE), u8(NONCE)),
    generateRootKey: KeyManager.generateRootKey(),
    decodeBackupCode: KeyManager.decodeBackupCode(backupCode),
    sign: sign(u8(MESSAGE), u8(keypair.secretKey)),
    deriveMasterKeyFromRootKey: deriveMasterKeyFromRootKey(u8(rootKey)),
  })) {
    assert.ok(Buffer.isBuffer(value), label)
  }
})

// The root key is held as a view, so a caller that zeroes its own buffer leaves
// no plaintext copy behind. The master key is deliberately the other way round:
// it is copied into sodium_malloc'd memory.
test('the root key is referenced, the master key is copied', () => {
  const callerRootKey = Uint8Array.from(rootKey)
  const callerMasterKey = Uint8Array.from(masterKey)
  const km = new KeyManager(callerRootKey, { masterKey: callerMasterKey })

  callerMasterKey.fill(0)
  assert.deepEqual(km.getMasterKey(), masterKey, 'master key was copied')

  callerRootKey.fill(0)
  assert.notEqual(
    km.getIdentityBackupCode(),
    backupCode,
    'root key was not copied',
  )
})
