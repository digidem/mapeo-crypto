// @ts-check
const sodium = require('sodium-universal')

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
exports.verify = function (message, signature, publicKey) {
  return sodium.crypto_sign_verify_detached(signature, message, publicKey)
}
