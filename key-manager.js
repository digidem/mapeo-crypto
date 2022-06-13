// @ts-check
const sodium = require('sodium-native')
const assert = require('assert')
const {
  deriveMasterKeyFromRootKey,
  deriveNamedKey,
  signKeypair,
} = require('./lib/key-utils')
const StringEncoding = require('./lib/string-encoding')
const ByteEncoding = require('./lib/byte-encoding')
const calculateCrc16 = require('crc/lib/crc16_ccitt')

const ROOTKEY_BYTES = 16
const BACKUP_CODE_IDENTIFIER = 'M'

/** @typedef {import('./lib/key-utils').Keypair} Keypair */

/**
 * The KeyManager class derives the key pairs used for identifying the device
 * and for all the hypercores on the device. All the key pairs are generated
 * deterministically from a single 16-byte root key. The backup code can be
 * used to backup this identity and recover it on a new device. The root key
 * and backup code must be kept secret at all times - someone who has this key
 * can impersonate the user to another Mapeo user.
 */
class KeyManager {
  /** @private */
  _masterKey
  /** @private */
  _rootKey

  /**
   * @param {Buffer} rootKey 16-bytes of random data that uniquely identify the device, used to derive a 32-byte master key, which is used to derive all the keypairs used for Mapeo
   */
  constructor(rootKey) {
    assert(
      rootKey.length === ROOTKEY_BYTES,
      `rootKey must be ${ROOTKEY_BYTES} bytes`
    )
    this._rootKey = rootKey
    this._masterKey = deriveMasterKeyFromRootKey(rootKey)
  }

  /**
   * Generate a deterministic ed25519 signing keypair that uniquely identifies
   * this device. Used for identifying the device on the network to other peers.
   *
   * @returns {Keypair}
   */
  getIdentityKeypair() {
    return this._signingKeypair('identity')
  }

  getIdentityBackupCode() {
    const crc16 = calculateCrc16(this._rootKey)
    const encodedBackupCode = ByteEncoding.backupCode.encode({
      rootKey: this._rootKey,
      crc16,
    })
    return (
      BACKUP_CODE_IDENTIFIER + StringEncoding.base32.encode(encodedBackupCode)
    )
  }

  /**
   * Generate a deterministic signing keypair for a given project key and name.
   * API compatible with Corestore-next.
   *
   * @param {string} name Local name for the keypair
   * @param {Buffer} namespace 32-byte namespace
   * @returns {Keypair}
   */
  getHypercoreKeypair(name, namespace) {
    // TODO: For hypercore-next return a sign function
    return this._signingKeypair(name, namespace)
  }

  /**
   * Generate a derived keypair for the given name. Deterministic: the same
   * keypair will be generated for the same name if the identity key is the
   * same.
   * @private
   *
   * @param {string} name
   * @param {Buffer} [token] Optional 32-byte token to use for key derivation, e.g. to namespace keys.
   * @returns {Keypair}
   */
  _signingKeypair(name, token) {
    // TODO: Cache / memoize keypair generation? Is this expensive?
    const seed = deriveNamedKey(this._masterKey, name, token)
    return signKeypair(seed)
  }

  /**
   * Generate a new random identity key. This is used to derive a master key:
   * all keys are deterministically derived from this identity key, so this
   * should only be used once on each device and the key should be securely
   * stored.
   *
   * @returns {Buffer}
   */
  static generateRootKey() {
    const buf = sodium.sodium_malloc(ROOTKEY_BYTES)
    sodium.randombytes_buf(buf)
    return buf
  }

  /**
   * Decode the root key from a backup code. Throws an error if the CRC
   * check fails.
   *
   * @param {string} stringEncodedBackupCode
   * @returns {Buffer} The 16-byte root key encoded in the backup code
   */
  static decodeBackupCode(stringEncodedBackupCode) {
    assert(
      stringEncodedBackupCode.startsWith(BACKUP_CODE_IDENTIFIER),
      'Invalid backup code: must start with ' + BACKUP_CODE_IDENTIFIER
    )
    assert(
      stringEncodedBackupCode.length === 30,
      'Invalid backup code: must be 30 characters'
    )
    let byteEncodedBackupCode
    try {
      byteEncodedBackupCode = StringEncoding.base32.decode(
        stringEncodedBackupCode.slice(1)
      )
    } catch (err) {
      throw new Error('Invalid backup code: invalid base32 encoding')
    }
    let rootKey
    let crc16
    try {
      const backupCode = ByteEncoding.backupCode.decode(byteEncodedBackupCode)
      rootKey = backupCode.rootKey
      crc16 = backupCode.crc16
    } catch (err) {
      /* istanbul ignore next - can't find a way to reach here, since assertions will throw before this */
      throw new Error('Invalid backup code: invalid byte encoding')
    }
    const calculatedCrc16 = calculateCrc16(rootKey)
    if (crc16 !== calculatedCrc16) {
      throw new Error(`Invalid backup code: CRC mismatch`)
    }
    return rootKey
  }

  static BACKUP_CODE_IDENTIFIER = BACKUP_CODE_IDENTIFIER
}

module.exports = KeyManager
