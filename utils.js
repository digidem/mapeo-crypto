// @ts-check
const sodium = require('sodium-universal')
const z32 = require('z32')

const MAPEO = Buffer.from('mapeo')

/**
 * Sign message using secretKey
 *
 * @param {Buffer} message
 * @param {Buffer} secretKey
 */
exports.sign = function (message, secretKey) {
  const signature = Buffer.allocUnsafe(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, message, secretKey)
  return signature
}

/**
 * Verify if the message signature is valid
 *
 * @param {Buffer} message
 * @param {Buffer} signature
 * @param {Buffer} publicKey public key of keypair used to sign message
 * @returns {boolean}
 */
exports.verifySignature = function (message, signature, publicKey) {
  return sodium.crypto_sign_verify_detached(signature, message, publicKey)
}

/**
 * Get a project public ID from the project key. The project public ID is a hash
 * of the project key and safe to share publicly. The hash is encoded as
 * [z-base-32](http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt)
 *
 * @param {Buffer} projectKey
 * @returns {string} z-base-32 encoded hash of the project key
 */
exports.projectKeyToPublicId = function (projectKey) {
  const digest = Buffer.allocUnsafe(32)
  sodium.crypto_generichash(digest, MAPEO, projectKey)
  return z32.encode(digest)
}
