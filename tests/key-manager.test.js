// @ts-check
import test from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'crypto'
import KeyManager from '../key-manager.js'
import { validateSignKeypair } from '../lib/key-utils.js'
import Hypercore from 'hypercore'
import RAM from 'random-access-memory'

test('encoding backup code', () => {
  const rootKey = KeyManager.generateRootKey()
  const km = new KeyManager(rootKey)
  const backupCode = km.getIdentityBackupCode()
  assert.ok(typeof backupCode === 'string', 'is a string')
  assert.ok(backupCode.length === 30, '30 characters long')
  assert.ok(
    backupCode.startsWith(KeyManager.BACKUP_CODE_IDENTIFIER),
    'starts with ' + KeyManager.BACKUP_CODE_IDENTIFIER
  )
})

test('decoding backup code', () => {
  const rootKey = KeyManager.generateRootKey()
  const km = new KeyManager(rootKey)
  const backupCode = km.getIdentityBackupCode()
  const decoded = KeyManager.decodeBackupCode(backupCode)
  assert.ok(decoded.equals(rootKey))
})

test('invalid backup codes', () => {
  const rootKey = KeyManager.generateRootKey()
  const km = new KeyManager(rootKey)
  const validBackupCode = km.getIdentityBackupCode()

  const invalidBackupCodes = [
    '',
    // Not base 32
    'aNz3@-U_gVPLfnqQ',
    // Not base 32 but starts with M
    'Mni9s*D8-Gbv9.xiz',
    // Not base 32 but starts with M and is 30 characters
    'ML_hPa3@dDi6aWuY7q2agoHx9u2gaX',
    // base 32 but not 30 characters
    'MHYDGXENRVKWVZE5JWS6J2XF58JFH',
    // base 32 but doesn't start with M
    'B8GWDNX8FV8VN2W99D6PJ0P9K6DKM7',
    // base 32 30 random characters starting with M
    'MBTB907WX14S4XVZE9TH0AEKPES2R8',
    // transcription error
    validBackupCode.slice(0, 5) +
      (validBackupCode.charAt(5) === 'W' ? 'V' : 'W') +
      validBackupCode.slice(6)
  ]

  for (const code of invalidBackupCodes) {
    assert.throws(() => KeyManager.decodeBackupCode(code), /invalid/i)
  }
})

test('identity keypair', () => {
  const rootKey = KeyManager.generateRootKey()
  const km1 = new KeyManager(rootKey)
  const km2 = new KeyManager(rootKey)
  assert.deepEqual(km1.getIdentityKeypair(), km2.getIdentityKeypair())
  assert.ok(validateSignKeypair(km1.getIdentityKeypair()))
})

test('determenistic derive swarm keypair for today', () => {
  const rootKey = KeyManager.generateRootKey()
  const km1 = new KeyManager(rootKey)
  const km2 = new KeyManager(rootKey)
  assert.deepEqual(km1.deriveSwarmIdentity(), km2.deriveSwarmIdentity())
  assert.ok(validateSignKeypair(km1.deriveSwarmIdentity()))
})

test('determenistic derive swarm keypair for specific date', () => {
  const rootKey = KeyManager.generateRootKey()
  const km1 = new KeyManager(rootKey)
  const km2 = new KeyManager(rootKey)
  const date = new Date(0)
  assert.deepEqual(km1.deriveSwarmIdentity(date), km2.deriveSwarmIdentity(date))
  assert.ok(validateSignKeypair(km1.deriveSwarmIdentity()))
})

test('hypercore keypair', () => {
  const rootKey = KeyManager.generateRootKey()
  const namespace = Buffer.alloc(32, 5)
  const km1 = new KeyManager(rootKey)
  const km2 = new KeyManager(rootKey)
  assert.ok(validateSignKeypair(km1.getHypercoreKeypair('foo', namespace)))
  assert.deepEqual(
    km1.getHypercoreKeypair('foo', namespace),
    km2.getHypercoreKeypair('foo', namespace)
  )
})

test('deterministic getDerivedKey', () => {
  const rootKey = KeyManager.generateRootKey()
  const namespace = Buffer.alloc(32, 5)
  const km1 = new KeyManager(rootKey)
  const km2 = new KeyManager(rootKey)
  assert.deepEqual(
    km1.getDerivedKey('foo', namespace),
    km2.getDerivedKey('foo', namespace)
  )
})

test('encrypt and decrypt', () => {
  const message = Buffer.from('hello world')
  const rootKey = KeyManager.generateRootKey()
  const km = new KeyManager(rootKey)
  const nonce = randomBytes(24)

  const cypher = km.encryptLocalMessage(message, nonce)
  // Not testing cryptographic security, but at least avoiding silly mistakes
  assert.notEqual(
    cypher,
    message,
    'encrypted data is not the same as original message'
  )
  const decrypted = km.decryptLocalMessage(cypher, nonce)
  assert.deepEqual(decrypted, message, 'message correctly decrypted')
})

test('projectKeypair can be used to create a hypercore', async () => {
  /** @type {Record<string, RAM>} */
  const st = {}
  const keyPair = KeyManager.generateProjectKeypair()
  // @ts-ignore
  const core = new Hypercore(open, { keyPair, valueEncoding: 'utf-8' })
  await core.ready()
  await core.append('hello')

  // re-open hypercore with keypair and check we can still write to it
  // @ts-ignore
  const reopen = new Hypercore(open, { keyPair, valueEncoding: 'utf-8' })
  await reopen.ready()
  await reopen.append('world')

  const blocks = await Promise.all([reopen.get(0), reopen.get(1)])
  assert.deepEqual(blocks, ['hello', 'world'])

  await reopen.close()

  /** @param {string} name */
  function open (name) {
    if (st[name]) return st[name]
    st[name] = new RAM()
    return st[name]
  }
})

test('projectKeypair is non-deterministic (always changes)', () => {
  // Not a strong test, but catches an error where we might pass a seed
  // internally so that the same keypair is always generated
  const keypair1 = KeyManager.generateProjectKeypair()
  const keypair2 = KeyManager.generateProjectKeypair()
  assert.notDeepEqual(keypair1, keypair2, 'keys are different')
})
