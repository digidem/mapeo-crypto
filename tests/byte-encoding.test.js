import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'crypto'
import * as ByteEncoding from '../src/lib/byte-encoding.js'

test('can encode and decode a backup code', () => {
  const data = { rootKey: crypto.randomBytes(16), crc16: 0xabcd }
  const encoded = ByteEncoding.backupCode.encode(data)
  assert.equal(encoded.length, 18)
  assert.deepEqual(ByteEncoding.backupCode.decode(encoded), data)
})

test('trying to decode a backup code of invalid length throws', () => {
  for (const length of [0, 17, 19, 128]) {
    assert.throws(
      () => ByteEncoding.backupCode.decode(crypto.randomBytes(length)),
      /invalid backup code/i,
      `length ${length}`
    )
  }
})
