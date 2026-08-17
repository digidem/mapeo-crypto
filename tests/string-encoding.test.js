import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'crypto'
import { base32 } from '../src/lib/string-encoding.js'

test('round trips arbitrary bytes', () => {
  for (const length of [1, 2, 3, 5, 16, 18, 32]) {
    const buf = crypto.randomBytes(length)
    assert.deepEqual(base32.decode(base32.encode(buf)), buf, `length ${length}`)
  }
})

test('decoding is case insensitive', () => {
  const buf = crypto.randomBytes(18)
  const encoded = base32.encode(buf)
  assert.equal(encoded, encoded.toUpperCase(), 'encodes as uppercase')
  assert.deepEqual(base32.decode(encoded.toLowerCase()), buf)
})

// The whole reason this module uses Crockford's alphabet rather than RFC 4648.
// A swap would keep every round-trip test green and silently cost users their
// ability to recover a mis-read backup code.
test('decoding forgives confusable characters', () => {
  const buf = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex')
  const encoded = base32.encode(buf)
  assert.ok(encoded.includes('0') && encoded.includes('1'), 'fixture is useful')
  assert.deepEqual(base32.decode(encoded.replace(/0/g, 'O')), buf, 'O for 0')
  assert.deepEqual(base32.decode(encoded.replace(/1/g, 'I')), buf, 'I for 1')
  assert.deepEqual(base32.decode(encoded.replace(/1/g, 'L')), buf, 'L for 1')
})

test('decoding rejects strings outside the alphabet', () => {
  for (const str of ['', 'abc def', 'abc-def', 'abc_def', 'abc!', '@']) {
    assert.throws(() => base32.decode(str), /Invalid base32 string/, str)
  }
})
