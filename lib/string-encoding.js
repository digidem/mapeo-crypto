const BASE62_CHARMAP =
  '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

import base32Encoding from 'base32.js'
import baseX from 'base-x'
import assert from 'assert/strict'

const base62Encoding = baseX(BASE62_CHARMAP)

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

export const base62 = {
  /** @type {(buf: Buffer) => string} */
  encode(buf) {
    return base62Encoding.encode(buf)
  },
  /** @type {(str: string) => Buffer} */
  decode(str) {
    return base62Encoding.decode(str)
  },
}
