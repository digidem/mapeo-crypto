// @ts-check
const { test } = require('tap')
const KeyManager = require('../key-manager')
const { validateSignKeypair } = require('../lib/key-utils')

test('encoding backup code', (t) => {
  const rootKey = KeyManager.generateRootKey()
  const km = new KeyManager(rootKey)
  const backupCode = km.getIdentityBackupCode()
  t.ok(typeof backupCode === 'string', 'is a string')
  t.ok(backupCode.length === 30, '30 characters long')
  t.ok(
    backupCode.startsWith(KeyManager.BACKUP_CODE_IDENTIFIER),
    'starts with ' + KeyManager.BACKUP_CODE_IDENTIFIER
  )
  t.end()
})

test('decoding backup code', (t) => {
  const rootKey = KeyManager.generateRootKey()
  const km = new KeyManager(rootKey)
  const backupCode = km.getIdentityBackupCode()
  const decoded = KeyManager.decodeBackupCode(backupCode)
  t.same(decoded, rootKey)
  t.end()
})

test('invalid backup codes', (t) => {
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
      validBackupCode.slice(6),
  ]

  for (const code of invalidBackupCodes) {
    t.throws(() => KeyManager.decodeBackupCode(code), /invalid/i)
  }
  t.end()
})

test('identity keypair', (t) => {
  const rootKey = KeyManager.generateRootKey()
  const km1 = new KeyManager(rootKey)
  const km2 = new KeyManager(rootKey)
  t.same(km1.getIdentityKeypair(), km2.getIdentityKeypair())
  t.ok(validateSignKeypair(km1.getIdentityKeypair()))
  t.end()
})

test('hypercore keypair', (t) => {
  const rootKey = KeyManager.generateRootKey()
  const namespace = Buffer.alloc(32, 5)
  const km1 = new KeyManager(rootKey)
  const km2 = new KeyManager(rootKey)
  t.ok(validateSignKeypair(km1.getHypercoreKeypair('foo', namespace)))
  t.same(
    km1.getHypercoreKeypair('foo', namespace),
    km2.getHypercoreKeypair('foo', namespace)
  )
  t.end()
})
