import base32Encoding from 'base32.js'
import assert from 'assert/strict'

/** @ignore */
export const base32 = {
  // Using crockford base32 alphabet and charmap for consistency with encoding
  // for IDs in Mapeo (we use crockford because it has better recovery of
  // mis-typed characters)
  /** @type {(buf: Buffer) => string} */
  encode(buf) {
    return base32Encoding.encode(buf, { type: 'crockford' })
  },
  /** @type {(str: string) => Buffer} */
  decode(str) {
    assert(/^[a-z0-9]+$/i.test(str), 'Invalid base32 string')
    const decoded = base32Encoding.decode(str, { type: 'crockford' })
    return decoded
  },
}
