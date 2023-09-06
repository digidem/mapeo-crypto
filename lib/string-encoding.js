// @ts-check
const base32 = require('base32.js')
const assert = require('assert')

module.exports = {
  // Using crockford base32 alphabet and charmap for consistency with encoding
  // for IDs in Mapeo (we use crockford because it has better recovery of
  // mis-typed characters)
  base32: {
    /** @type {(buf: Buffer) => string} */
    encode (buf) {
      return base32.encode(buf, { type: 'crockford' })
    },
    /** @type {(str: string) => Buffer} */
    decode (str) {
      assert(/^[a-z0-9]+$/i.test(str), 'Invalid base32 string')
      const decoded = base32.decode(str, { type: 'crockford' })
      return decoded
    }
  }
}
