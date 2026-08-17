import sodium from 'sodium-universal'
import assert from 'assert/strict'
import {
  deriveMasterKeyFromRootKey,
  deriveNamedKey,
  signKeypair,
} from './lib/key-utils.js'
import { base32 } from './lib/string-encoding.js'
import * as ByteEncoding from './lib/byte-encoding.js'
import calculateCrc16 from 'crc/crc16ccitt'

const ROOTKEY_BYTES = 16
const MASTERKEY_BYTES = 32
const BACKUP_CODE_IDENTIFIER = 'M'

/**
 * @import {Keypair} from './lib/key-utils.js'
 * @ignore
 */

/**
 * The KeyManager class derives the key pairs used for identifying the device
 * and for all the hypercores on the device. All the key pairs are generated
 * deterministically from a single 16-byte root key. The backup code can be
 * used to backup this identity and recover it on a new device. The root key
 * and backup code must be kept secret at all times - someone who has this key
 * can impersonate the user to another CoMapeo user.
 */
class KeyManager {
  #masterKey
  #rootKey

  /**
   * @param {Buffer} rootKey 16-bytes of random data that uniquely identify the device, used to derive a 32-byte master key, which is used to derive all the keypairs used for CoMapeo
   * @param {object} [opts]
   * @param {Uint8Array} [opts.masterKey] Previously derived 32-byte master key for this same `rootKey`, e.g. read from a cache. When provided the expensive derivation is skipped and this value is used directly. The caller is responsible for it actually being `deriveMasterKeyFromRootKey(rootKey)`: the pairing is trusted, not verified, because verifying it would mean running the derivation this option exists to avoid. A mismatched pair yields a working but *different* identity, whose backup code still encodes `rootKey`.
   */
  constructor(rootKey, { masterKey } = {}) {
    assert(
      rootKey.length === ROOTKEY_BYTES,
      `rootKey must be ${ROOTKEY_BYTES} bytes`,
    )
    this.#rootKey = rootKey
    if (masterKey) {
      assert(
        masterKey.length === MASTERKEY_BYTES,
        `masterKey must be ${MASTERKEY_BYTES} bytes`,
      )
      this.#masterKey = sodium.sodium_malloc(MASTERKEY_BYTES)
      // `set` rather than `copy`: this key often arrives from a native bridge
      // as a plain Uint8Array.
      this.#masterKey.set(masterKey)
    } else {
      this.#masterKey = deriveMasterKeyFromRootKey(rootKey)
    }
  }

  /**
   * The 32-byte master key from which every other key is derived. Returns a
   * copy, so the caller can zero it without touching the instance's secure
   * buffer.
   *
   * @returns {Buffer}
   */
  getMasterKey() {
    return Buffer.from(this.#masterKey)
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

  /**
   * Generate a deterministic ed25519 signing keypair that uniquely identifies
   * this device for the day. Used for identifying the device on hyperswarm.
   * Keys change every day to make it harder to track a specific device.
   * Keys persist accross app restarts.
   *
   * @param {Date} [date]
   * @returns {Keypair}
   */
  deriveSwarmIdentity(date = new Date()) {
    const keyName = `identity-${date.getFullYear()}-${date.getMonth()}-${date.getDate()}`
    return this._signingKeypair(keyName)
  }

  /**
   * The backup code for this device's identity: a string-encoded form of the
   * root key, for the user to write down. Depends only on the root key, so it
   * is unaffected by a `masterKey` passed to the constructor.
   *
   * @returns {string} 30-character backup code
   */
  getIdentityBackupCode() {
    const crc16 = calculateCrc16(this.#rootKey)
    const encodedBackupCode = ByteEncoding.backupCode.encode({
      rootKey: this.#rootKey,
      crc16,
    })
    return BACKUP_CODE_IDENTIFIER + base32.encode(encodedBackupCode)
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
   * Generate a derived key for the given name. Deterministic: the same
   * key will be generated for the same name if the identity key is the
   * same.
   *
   * @param {string} name
   * @param {Buffer} [token] Optional 32-byte token to use for key derivation, e.g. to namespace keys.
   * @returns {Buffer} 32-byte buffer
   */
  getDerivedKey(name, token) {
    return deriveNamedKey(this.#masterKey, name, token)
  }

  /**
   * Decrypt an encrypted message using the provided nonce parameter
   *
   * @param {Buffer} cyphertext
   * @param {Buffer} nonce 24-byte nonce
   */
  decryptLocalMessage(cyphertext, nonce) {
    const ABYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
    assert(
      cyphertext.length >= ABYTES,
      `cyphertext must be at least ${ABYTES} bytes`,
    )
    const msg = Buffer.alloc(cyphertext.length - ABYTES)
    // Throws if the tag does not verify - never returns unauthenticated bytes.
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      msg,
      null,
      cyphertext,
      null,
      nonce,
      this.#masterKey,
    )
    return msg
  }

  /**
   * Encrypt a message using the provided nonce parameter
   * This should only be used for encrypting local messages, not for sending
   * messages over the internet, because the nonce is non-random, so messages
   * could be subject to replay attacks
   *
   * @param {Buffer} msg
   * @param {Buffer} nonce 24-byte nonce
   */
  encryptLocalMessage(msg, nonce) {
    const cyphertext = Buffer.alloc(
      msg.length + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES,
    )
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      cyphertext,
      msg,
      null,
      null,
      nonce,
      this.#masterKey,
    )
    return cyphertext
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
    const seed = this.getDerivedKey(name, token)
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
   * Generate a keypair for a new project. The public key of this keypair
   * becomes the project key. The keypair should be used as the keypair for the
   * hypercore in the 'auth' namespace for the project creator.
   *
   * This keypair is non-deterministic, it must be persisted somewhere.
   */
  static generateProjectKeypair() {
    return signKeypair()
  }

  /**
   * Decode the root key from a backup code. Throws an error if the CRC
   * check fails.
   *
   * Input is normalized before validation, because backup codes are
   * transcribed by hand: case is ignored, and whitespace and hyphens (which
   * users add to group the code for legibility) are stripped. The base32
   * alphabet is Crockford's, so `O` reads as `0` and `I`/`L` as `1`.
   *
   * @param {string} stringEncodedBackupCode
   * @returns {Buffer} The 16-byte root key encoded in the backup code
   */
  static decodeBackupCode(stringEncodedBackupCode) {
    assert(
      typeof stringEncodedBackupCode === 'string',
      'Invalid backup code: must be a string',
    )
    const normalized = stringEncodedBackupCode
      .replace(/[\s-]/g, '')
      .toUpperCase()
    assert(
      normalized.startsWith(BACKUP_CODE_IDENTIFIER),
      'Invalid backup code: must start with ' + BACKUP_CODE_IDENTIFIER,
    )
    assert(
      normalized.length === 30,
      'Invalid backup code: must be 30 characters',
    )
    let byteEncodedBackupCode
    try {
      byteEncodedBackupCode = base32.decode(normalized.slice(1))
    } catch (err) {
      throw new Error('Invalid backup code: invalid base32 encoding', {
        cause: err,
      })
    }
    let rootKey
    let crc16
    try {
      const backupCode = ByteEncoding.backupCode.decode(byteEncodedBackupCode)
      rootKey = backupCode.rootKey
      crc16 = backupCode.crc16
    } catch (err) {
      /* istanbul ignore next - can't find a way to reach here, since assertions will throw before this */
      throw new Error('Invalid backup code: invalid byte encoding', {
        cause: err,
      })
    }
    const calculatedCrc16 = calculateCrc16(rootKey)
    if (crc16 !== calculatedCrc16) {
      throw new Error(`Invalid backup code: CRC mismatch`)
    }
    return rootKey
  }

  static BACKUP_CODE_IDENTIFIER = BACKUP_CODE_IDENTIFIER
}

export default KeyManager
