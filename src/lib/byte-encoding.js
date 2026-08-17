import cenc from 'compact-encoding'
import assert from 'assert/strict'

/**
 * @typedef {object} BackupCode
 * @property {Buffer} rootKey 16-byte buffer - identity master key for device
 * @property {number} crc16 16-bit crc16 checksum of rootKey
 * @ignore
 */

/** @ignore */
export const backupCode = {
  /** @type {(backupCode: BackupCode) => Buffer} */
  encode({ rootKey, crc16 }) {
    return Buffer.concat([rootKey, cenc.encode(cenc.uint16, crc16)])
  },
  /** @type {(buf: Buffer) => BackupCode} */
  decode(buf) {
    assert(buf.length === 16 + 2, 'Invalid backup code')
    const rootKey = buf.slice(0, 16)
    const crc16 = cenc.decode(cenc.uint16, buf.slice(16))
    return { rootKey, crc16 }
  },
}
