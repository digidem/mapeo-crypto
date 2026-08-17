import sodium from 'sodium-universal'
import z32 from 'z32'

const MAPEO = Buffer.from('mapeo')

/**
 * Sign message using secretKey
 *
 * @param {Uint8Array} message
 * @param {Uint8Array} secretKey
 * @returns {Buffer} 64-byte detached signature
 */
export function sign(message, secretKey) {
  const signature = Buffer.allocUnsafe(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, message, secretKey)
  return signature
}

/**
 * Verify if the message signature is valid
 *
 * @param {Uint8Array} message
 * @param {Uint8Array} signature
 * @param {Uint8Array} publicKey public key of keypair used to sign message
 * @returns {boolean}
 */
export function verifySignature(message, signature, publicKey) {
  return sodium.crypto_sign_verify_detached(signature, message, publicKey)
}

/**
 * Get a public ID from a key. The public ID is a hash
 * of the key and safe to share publicly. The hash is encoded as
 * [z-base-32](http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt)
 *
 * @param {Uint8Array} key
 * @returns {string} z-base-32 encoded hash of the key
 */
export function keyToPublicId(key) {
  const digest = Buffer.allocUnsafe(32)
  sodium.crypto_generichash(digest, MAPEO, key)
  return z32.encode(digest)
}
