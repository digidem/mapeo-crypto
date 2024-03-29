// @ts-check
const sodium = require('sodium-universal')
const assert = require('assert')

module.exports = {
  encryptMessage,
  decryptMessage,
}

/**
 * Encrypt a message for a recipient identified by `receiverPublicKey`. This is
 * an ed25519 signing key that is used to uniquely identify Mapeo devices.
 * Internally this signing key is converted to a curve25519 key for generating a
 * shared secret for encryption, similar to how Sodium Key Exchange works. The
 * sender's key pair should be ephemeral, and used only once.
 * @private
 *
 * @param {Buffer} message Invite message (encoded to buffer) to encrypt
 * @param {Buffer} senderPublicKey 32-byte public encryption key (curve25519). This should be an ephemeral key generated by the sender of the encrypted message.
 * @param {Buffer} senderSecretKey 32-byte secret encryption key (curve25519). This should be an ephemeral key generated by the sender of the encrypted message.
 * @param {Buffer} receiverPublicKey 32-byte public signing key (ed25519) from the recipient of the message
 * @returns {Buffer} Encrypted message
 */
function encryptMessage(
  message,
  senderPublicKey,
  senderSecretKey,
  receiverPublicKey
) {
  assert(
    senderPublicKey.length >= sodium.crypto_box_PUBLICKEYBYTES,
    `senderPublicKey must be at least ${sodium.crypto_box_PUBLICKEYBYTES} bytes`
  )
  assert(
    senderSecretKey.length >= sodium.crypto_box_SECRETKEYBYTES,
    `senderSecretKey must be at least ${sodium.crypto_box_SECRETKEYBYTES} bytes`
  )
  assert(
    receiverPublicKey.length >= sodium.crypto_sign_PUBLICKEYBYTES,
    `receiverPublicKey must be at least ${sodium.crypto_sign_PUBLICKEYBYTES} bytes`
  )

  // Generate an encryption key (X25519) from the signing key (Ed25519) that
  // we use for device identity
  const receiverEncryptPublicKey = Buffer.allocUnsafe(
    sodium.crypto_scalarmult_BYTES
  )
  sodium.crypto_sign_ed25519_pk_to_curve25519(
    receiverEncryptPublicKey,
    receiverPublicKey
  )

  const txKey = sodium.sodium_malloc(sodium.crypto_kx_SESSIONKEYBYTES)
  sodium.crypto_kx_server_session_keys(
    null,
    txKey,
    senderPublicKey,
    senderSecretKey,
    receiverEncryptPublicKey
  )
  const nonce = generateNonce(senderPublicKey, receiverPublicKey)
  const encryptedMessage = Buffer.allocUnsafe(
    message.length + sodium.crypto_secretbox_MACBYTES
  )
  sodium.crypto_secretbox_easy(encryptedMessage, message, nonce, txKey)
  return encryptedMessage
}

/**
 * Decrypt a message encrypted with `encryptMessage()`. The receiver key pair
 * should be the ed25519 keypair used to uniquely identify the device. The
 * sender public key should be an ephemeral Curve25519 encryption key that is
 * sent along with the encrypted message.
 * @private
 *
 * @param {Buffer} encryptedMessage Encrypted message (encoded to buffer)
 * @param {Buffer} receiverPublicKey 32-byte signing public key (ed25519)
 * @param {Buffer} receiverSecretKey 32-byte signing secret key (ed25519)
 * @param {Buffer} senderPublicKey 32-byte encryption public key (curve25519)
 * @returns {Buffer} Decrypted message
 */
function decryptMessage(
  encryptedMessage,
  receiverPublicKey,
  receiverSecretKey,
  senderPublicKey
) {
  assert(
    receiverSecretKey.length >= sodium.crypto_sign_SECRETKEYBYTES,
    `joinerSignSecretKey must be at least ${sodium.crypto_sign_SECRETKEYBYTES} bytes`
  )
  assert(
    senderPublicKey.length >= sodium.crypto_sign_PUBLICKEYBYTES,
    `inviterPublicKey must be at least ${sodium.crypto_sign_PUBLICKEYBYTES} bytes`
  )
  assert(
    encryptedMessage.length > sodium.crypto_box_MACBYTES,
    'encryptedMsg must be greater than 16 bytes'
  )
  // Generate an encryption key (X25519) from the signing key (Ed25519) that
  // we use for device identity
  const receiverEncryptPublicKey = Buffer.allocUnsafe(
    sodium.crypto_box_PUBLICKEYBYTES
  )
  sodium.crypto_sign_ed25519_pk_to_curve25519(
    receiverEncryptPublicKey,
    receiverPublicKey
  )
  const receiverEncryptSecretKey = sodium.sodium_malloc(
    sodium.crypto_box_SECRETKEYBYTES
  )
  sodium.crypto_sign_ed25519_sk_to_curve25519(
    receiverEncryptSecretKey,
    receiverSecretKey
  )

  const rxKey = sodium.sodium_malloc(sodium.crypto_kx_SESSIONKEYBYTES)
  sodium.crypto_kx_client_session_keys(
    rxKey,
    null,
    receiverEncryptPublicKey,
    receiverEncryptSecretKey,
    senderPublicKey
  )
  const nonce = generateNonce(senderPublicKey, receiverPublicKey)

  // Use alloc() here to ensure that we start with an empty buffer in case for
  // some reason the decrypted message is shorted than this (it shouldn't be!)
  const message = Buffer.alloc(
    encryptedMessage.length - sodium.crypto_secretbox_MACBYTES
  )
  if (
    !sodium.crypto_secretbox_open_easy(message, encryptedMessage, nonce, rxKey)
  ) {
    throw new Error('Failed to decrypt secret message')
  }
  return message
}

/**
 * Generate a nonce based on the ephemeral public key of the keypair used for
 * encryption, and the public key of the recipient of the message. This is
 * similar to the algorythm used for sealed box encryption.
 *
 * Since the sender generates a new ephemeral key pair for each message, this
 * ensures that the nonce is different for every message sent.
 *
 * @private
 *
 * @param {Buffer} senderPublicKey
 * @param {Buffer} receiverPublicKey
 * @returns {Buffer}
 */
function generateNonce(senderPublicKey, receiverPublicKey) {
  // We're just storing the first 24 bytes of the hash to use as the nonce
  const output = Buffer.allocUnsafe(sodium.crypto_secretbox_NONCEBYTES)
  sodium.crypto_generichash_batch(output, [senderPublicKey, receiverPublicKey])
  return output
}
