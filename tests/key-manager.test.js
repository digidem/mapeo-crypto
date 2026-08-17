import test from 'node:test'
import assert from 'node:assert/strict'
import KeyManager from '../src/key-manager.js'
import {
  deriveMasterKeyFromRootKey,
  validateSignKeypair,
} from '../src/lib/key-utils.js'
import Hypercore from 'hypercore'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DEVICE_A, DEVICE_B, keyManagerFor } from './fixtures.js'

const NAMESPACE_1 = Buffer.alloc(32, 1)
const NAMESPACE_2 = Buffer.alloc(32, 2)

test('constructor rejects invalid key lengths', () => {
  assert.throws(() => new KeyManager(Buffer.alloc(15)), /rootKey must be 16/)
  assert.throws(() => new KeyManager(Buffer.alloc(32)), /rootKey must be 16/)
  assert.throws(
    () => new KeyManager(DEVICE_A.rootKey, { masterKey: Buffer.alloc(31) }),
    /masterKey must be 32/,
  )
  assert.throws(
    () => new KeyManager(DEVICE_A.rootKey, { masterKey: Buffer.alloc(33) }),
    /masterKey must be 32/,
  )
})

test('generateRootKey', () => {
  assert.equal(KeyManager.generateRootKey().length, 16)
  assert.notDeepEqual(
    KeyManager.generateRootKey(),
    KeyManager.generateRootKey(),
  )
})

// This doubles as the determinism test for every method: `derived` runs the
// real Argon2id derivation, `supplied` skips it, and everything they produce
// has to match. A separate "same rootKey twice" test per method would only
// re-assert this at ~240ms each.
test('supplied masterKey is equivalent to deriving it', async (t) => {
  const derived = new KeyManager(DEVICE_A.rootKey)
  const supplied = new KeyManager(DEVICE_A.rootKey, {
    masterKey: deriveMasterKeyFromRootKey(DEVICE_A.rootKey),
  })
  const date = new Date(0)

  await t.test('identity keypair', () => {
    assert.deepEqual(
      derived.getIdentityKeypair(),
      supplied.getIdentityKeypair(),
    )
  })

  await t.test('swarm identity', () => {
    assert.deepEqual(
      derived.deriveSwarmIdentity(date),
      supplied.deriveSwarmIdentity(date),
    )
  })

  await t.test('hypercore keypair', () => {
    assert.deepEqual(
      derived.getHypercoreKeypair('foo', NAMESPACE_1),
      supplied.getHypercoreKeypair('foo', NAMESPACE_1),
    )
  })

  await t.test('derived key', () => {
    assert.deepEqual(
      derived.getDerivedKey('foo', NAMESPACE_1),
      supplied.getDerivedKey('foo', NAMESPACE_1),
    )
  })

  await t.test('identity backup code', () => {
    assert.equal(
      derived.getIdentityBackupCode(),
      supplied.getIdentityBackupCode(),
    )
  })

  await t.test('local message encryption interoperates', () => {
    const message = Buffer.from('hello world')
    const nonce = Buffer.alloc(24, 7)
    assert.deepEqual(
      supplied.decryptLocalMessage(
        derived.encryptLocalMessage(message, nonce),
        nonce,
      ),
      message,
    )
    assert.deepEqual(
      derived.decryptLocalMessage(
        supplied.encryptLocalMessage(message, nonce),
        nonce,
      ),
      message,
    )
  })
})

test('supplied masterKey accepts a plain Uint8Array', () => {
  // The cache this option exists for reaches us across a native bridge, which
  // does not necessarily hand back a Buffer.
  const km = new KeyManager(DEVICE_A.rootKey, {
    masterKey: new Uint8Array(DEVICE_A.masterKey),
  })
  assert.deepEqual(km.getMasterKey(), DEVICE_A.masterKey)
})

test('a masterKey that does not match its rootKey is trusted, not verified', () => {
  // Documented as the caller's problem. Pinning the shape of the damage: every
  // key follows the masterKey, but the backup code follows the rootKey, so the
  // code the user writes down restores a different identity entirely.
  const mismatched = new KeyManager(DEVICE_A.rootKey, {
    masterKey: DEVICE_B.masterKey,
  })
  assert.deepEqual(
    mismatched.getIdentityKeypair(),
    keyManagerFor(DEVICE_B).getIdentityKeypair(),
    'identity follows the masterKey',
  )
  assert.equal(
    mismatched.getIdentityBackupCode(),
    DEVICE_A.backupCode,
    'backup code follows the rootKey',
  )
})

test('masterKey getter returns a fresh copy', () => {
  const km = keyManagerFor(DEVICE_A)
  assert.deepEqual(km.getMasterKey(), DEVICE_A.masterKey)
  km.getMasterKey().fill(0)
  assert.deepEqual(
    km.getMasterKey(),
    DEVICE_A.masterKey,
    'instance is unaffected',
  )
  assert.notEqual(
    km.getMasterKey(),
    km.getMasterKey(),
    'a new buffer each call',
  )
})

test('keypairs are valid ed25519 keypairs', () => {
  const km = keyManagerFor(DEVICE_A)
  assert.ok(validateSignKeypair(km.getIdentityKeypair()), 'identity')
  assert.ok(validateSignKeypair(km.deriveSwarmIdentity(new Date(0))), 'swarm')
  assert.ok(
    validateSignKeypair(km.getHypercoreKeypair('foo', NAMESPACE_1)),
    'hypercore',
  )
  assert.ok(validateSignKeypair(KeyManager.generateProjectKeypair()), 'project')
})

test('different root keys give different identities', () => {
  const a = keyManagerFor(DEVICE_A)
  const b = keyManagerFor(DEVICE_B)
  assert.notDeepEqual(a.getIdentityKeypair(), b.getIdentityKeypair())
  assert.notDeepEqual(
    a.getHypercoreKeypair('auth', NAMESPACE_1),
    b.getHypercoreKeypair('auth', NAMESPACE_1),
  )
  assert.notDeepEqual(
    a.getDerivedKey('primaryKey', NAMESPACE_1),
    b.getDerivedKey('primaryKey', NAMESPACE_1),
  )
  assert.notEqual(a.getIdentityBackupCode(), b.getIdentityBackupCode())
})

// Dropping the token would leave every determinism test green while giving
// every project on a device the same writer keypair per namespace.
test('derived keys are namespaced by name and token', () => {
  const km = keyManagerFor(DEVICE_A)
  assert.notDeepEqual(
    km.getDerivedKey('a', NAMESPACE_1),
    km.getDerivedKey('b', NAMESPACE_1),
    'name is used',
  )
  assert.notDeepEqual(
    km.getDerivedKey('a', NAMESPACE_1),
    km.getDerivedKey('a', NAMESPACE_2),
    'token is used',
  )
  assert.notDeepEqual(
    km.getDerivedKey('a', NAMESPACE_1),
    km.getDerivedKey('a'),
    'a token is not the same as no token',
  )
})

test('hypercore keypairs are namespaced by name and token', () => {
  const km = keyManagerFor(DEVICE_A)
  assert.notDeepEqual(
    km.getHypercoreKeypair('a', NAMESPACE_1),
    km.getHypercoreKeypair('b', NAMESPACE_1),
    'name is used',
  )
  assert.notDeepEqual(
    km.getHypercoreKeypair('a', NAMESPACE_1),
    km.getHypercoreKeypair('a', NAMESPACE_2),
    'token is used',
  )
  assert.notDeepEqual(
    km.getHypercoreKeypair('identity', NAMESPACE_1),
    km.getIdentityKeypair(),
    'cannot collide with the device identity',
  )
})

test('swarm identity rotates daily', () => {
  const km = keyManagerFor(DEVICE_A)
  const morning = new Date(2024, 1, 29, 0, 0)
  const evening = new Date(2024, 1, 29, 23, 59)
  const nextDay = new Date(2024, 2, 1)

  assert.deepEqual(
    km.deriveSwarmIdentity(morning),
    km.deriveSwarmIdentity(evening),
    'stable across a single day',
  )
  assert.notDeepEqual(
    km.deriveSwarmIdentity(morning),
    km.deriveSwarmIdentity(nextDay),
    'rotates between days',
  )
  assert.notDeepEqual(
    km.deriveSwarmIdentity(morning),
    km.getIdentityKeypair(),
    'is not the long-lived device identity',
  )
})

// Pins the key name format, including the zero-indexed, unpadded month, which
// looks wrong enough that someone might "fix" it. Dates are built from local
// components because the key name is derived from local ones - a device that
// changes timezone rolls its swarm identity early or late.
test('pinned swarm identity vector', () => {
  assert.equal(
    keyManagerFor(DEVICE_A)
      .deriveSwarmIdentity(new Date(2024, 1, 29))
      .publicKey.toString('hex'),
    '7b653d582a5e6b9a183185e44301b174a313abd429c9f899d49125c6a0081e5d',
  )
})

test('pinned backup code vectors', () => {
  // Backup codes are written down on paper: unlike every other value here, a
  // change to this encoding cannot be migrated.
  for (const { rootKey, masterKey, backupCode } of [DEVICE_A, DEVICE_B]) {
    const km = new KeyManager(rootKey, { masterKey })
    assert.equal(km.getIdentityBackupCode(), backupCode)
    assert.deepEqual(KeyManager.decodeBackupCode(backupCode), rootKey)
  }
})

test('backup code round trips for a random root key', () => {
  const rootKey = KeyManager.generateRootKey()
  const backupCode = new KeyManager(rootKey).getIdentityBackupCode()
  assert.equal(backupCode.length, 30, '30 characters long')
  assert.ok(
    backupCode.startsWith(KeyManager.BACKUP_CODE_IDENTIFIER),
    'starts with ' + KeyManager.BACKUP_CODE_IDENTIFIER,
  )
  assert.ok(KeyManager.decodeBackupCode(backupCode).equals(rootKey))
})

// The reason lib/string-encoding.js uses Crockford's alphabet. Nothing else
// would fail if this stopped working.
test('decoding a backup code tolerates transcription', () => {
  const { backupCode, rootKey } = DEVICE_A
  const group = (/** @type {string} */ separator) =>
    backupCode.replace(/(.{5})(?=.)/g, '$1' + separator)
  const variants = {
    lowercase: backupCode.toLowerCase(),
    'O read back as 0': backupCode.replace(/0/g, 'O'),
    'I read back as 1': backupCode.replace(/1/g, 'I'),
    'L read back as 1': backupCode.replace(/1/g, 'L'),
    'grouped with hyphens': group('-'),
    'grouped with spaces': group(' '),
    'surrounding whitespace': `  ${backupCode}\n`,
  }
  for (const [name, variant] of Object.entries(variants)) {
    assert.deepEqual(KeyManager.decodeBackupCode(variant), rootKey, name)
  }
})

test('invalid backup codes', () => {
  const { backupCode } = DEVICE_A
  const invalidBackupCodes = [
    '',
    // Not base 32
    'aNz3@_U_gVPLfnqQ',
    // Not base 32 but starts with M
    'Mni9s*D8_Gbv9.xiz',
    // Not base 32 but starts with M and is 30 characters
    'ML_hPa3@dDi6aWuY7q2agoHx9u2gaX',
    // base 32 but not 30 characters
    'MHYDGXENRVKWVZE5JWS6J2XF58JFH',
    // base 32 but doesn't start with M
    'B8GWDNX8FV8VN2W99D6PJ0P9K6DKM7',
    // base 32 30 random characters starting with M
    'MBTB907WX14S4XVZE9TH0AEKPES2R8',
    // transcription error the checksum has to catch
    backupCode.slice(0, 5) +
      (backupCode.charAt(5) === 'W' ? 'V' : 'W') +
      backupCode.slice(6),
  ]

  for (const code of invalidBackupCodes) {
    assert.throws(() => KeyManager.decodeBackupCode(code), /invalid/i, code)
  }
})

test('decodeBackupCode rejects a non-string', () => {
  for (const notAString of [undefined, null, 12345, Buffer.alloc(30)]) {
    assert.throws(
      // @ts-expect-error - testing the runtime guard on a misuse the types forbid
      () => KeyManager.decodeBackupCode(notAString),
      /Invalid backup code: must be a string/,
    )
  }
})

test('encrypt and decrypt', () => {
  const km = keyManagerFor(DEVICE_A)
  const nonce = Buffer.alloc(24, 7)

  for (const message of [Buffer.from('hello world'), Buffer.alloc(0)]) {
    const cypher = km.encryptLocalMessage(message, nonce)
    assert.notDeepEqual(cypher, message, 'cyphertext differs from plaintext')
    assert.deepEqual(km.decryptLocalMessage(cypher, nonce), message)
  }
})

// MapeoManager decrypts every project's keys out of SQLite at startup, so a
// failed authentication has to throw rather than yield unauthenticated bytes.
test('decryption fails loudly', () => {
  const km = keyManagerFor(DEVICE_A)
  const nonce = Buffer.alloc(24, 7)
  const cypher = km.encryptLocalMessage(Buffer.from('hello world'), nonce)

  const tampered = Buffer.from(cypher)
  tampered[0] ^= 1
  assert.throws(
    () => km.decryptLocalMessage(tampered, nonce),
    /could not verify data/,
    'tampered cyphertext',
  )
  assert.throws(
    () => km.decryptLocalMessage(cypher, Buffer.alloc(24, 8)),
    /could not verify data/,
    'wrong nonce',
  )
  assert.throws(
    () => keyManagerFor(DEVICE_B).decryptLocalMessage(cypher, nonce),
    /could not verify data/,
    'wrong master key',
  )
  assert.throws(
    () => km.decryptLocalMessage(cypher.subarray(0, 15), nonce),
    /cyphertext must be at least 16 bytes/,
    'truncated cyphertext, e.g. a bad read - a length error, not a RangeError',
  )
})

test('projectKeypair can be used to create a hypercore', async (t) => {
  const storage = await mkdtemp(join(tmpdir(), 'comapeo-crypto-'))
  t.after(() => rm(storage, { recursive: true, force: true }))

  const keyPair = KeyManager.generateProjectKeypair()
  // @ts-ignore
  const core = new Hypercore(storage, { keyPair, valueEncoding: 'utf-8' })
  await core.ready()
  await core.append('hello')
  await core.close()

  // re-open hypercore with keypair and check we can still write to it
  // @ts-ignore
  const reopen = new Hypercore(storage, { keyPair, valueEncoding: 'utf-8' })
  await reopen.ready()
  await reopen.append('world')

  const blocks = await Promise.all([reopen.get(0), reopen.get(1)])
  assert.deepEqual(blocks, ['hello', 'world'])

  await reopen.close()
})

test('projectKeypair is non-deterministic (always changes)', () => {
  // Not a strong test, but catches an error where we might pass a seed
  // internally so that the same keypair is always generated
  const keypair1 = KeyManager.generateProjectKeypair()
  const keypair2 = KeyManager.generateProjectKeypair()
  assert.notDeepEqual(keypair1, keypair2, 'keys are different')
})
