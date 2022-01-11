// @ts-check
const ByteEncoding = require('./lib/byte-encoding')
const { encryptMessage, decryptMessage } = require('./lib/invite-utils')
const { boxKeypair } = require('./lib/key-utils')
const StringEncoding = require('./lib/string-encoding')

/** @typedef {'base32' | 'base62'} StringEncoding */
/** @typedef {import('./lib/byte-encoding').JoinRequest } JoinRequest */
/** @typedef {import('./lib/byte-encoding').InviteSecretMessage } InviteSecretMessage */

module.exports = {
  encodeJoinRequest,
  decodeJoinRequest,
  generateInvite,
  decodeInviteSecretMessage,
}

/**
 * Encode a join request encoded to a string for use in a QR code or a URL. A
 * join request includes (unencrypted) the identity public key of the device
 * sending the join request. The optional `name` is used to give context to the
 * receiver of the join request. It is unencrypted, so the user should not
 * reveal secret information in this field, or should ensure that the join
 * request is sent via a secure channel.
 *
 * `base32` is used for a QR code because it enables alphanumeric encoding
 * (uppercase A-Z, 0-9) which is more compact. `base62` is used for URLs, rather
 * than `base64`, because symbols like `+` can break URL parsing (e.g. in an SMS
 * message, only part of a URL before a `+` might be clickable).
 *
 * @param {JoinRequest} joinRequest A join request message
 * @param {Object} options
 * @param {StringEncoding} options.encoding Use base32 if using for an alphanumeric encoded QR Code (uppercase A-Z, 0-9), or base62 for a URL.
 * @returns {string} Encoded join request
 */
function encodeJoinRequest(joinRequest, { encoding }) {
  const byteEncodedJoinRequest = ByteEncoding.joinRequest.encode(joinRequest)
  return StringEncoding[encoding].encode(byteEncodedJoinRequest)
}

/**
 * Decode a join request from a string-encoded join request. Will throw if the
 * string does not encode a valid join request message.
 *
 * @param {string} str Join request encoded as a string
 * @param {Object} options
 * @param {StringEncoding} options.encoding Use base32 if using for an alphanumeric encoded QR Code (uppercase A-Z, 0-9), or base62 for a URL.
 * @returns {JoinRequest} Decoded join request
 */
function decodeJoinRequest(str, { encoding }) {
  // TODO: validate characters used in encoded string?
  const byteEncodedJoinRequest = StringEncoding[encoding].decode(str)
  return ByteEncoding.joinRequest.decode(byteEncodedJoinRequest)
}

/**
 * Generate an encrypted invite encoded as a string for use in a QR code or a
 * URL. Invites are encrypted and can only be decrypted by the owner of the
 * private key associated with the identity public key sent in the join request.
 *
 * `base32` is used for a QR code because it enables alphanumeric encoding
 * (uppercase A-Z, 0-9) which is more compact. `base62` is used for URLs, rather
 * than `base64`, because symbols like `+` can break URL parsing (e.g. in an SMS
 * message, only part of a URL before a `+` might be clickable).
 *
 * @param {import('./lib/byte-encoding').JoinRequest} joinRequest Decoded join request
 * @param {Object} options
 * @param {StringEncoding} options.encoding Use base32 if using for an alphanumeric encoded QR Code (uppercase A-Z, 0-9), or base62 for a URL.
 * @param {Buffer} options.projectKey Project key for project you wish to generate the invite for
 * @param {Buffer} [options.encryptionKey] Optional 32-byte encryption key for the project. This key is used to encrypt hypercore data on disk. Without this key a user will still be able to sync an encrypted project, but will not be able to read any data.
 * @returns {string} Encoded invite
 */
function generateInvite(joinRequest, { encoding, projectKey, encryptionKey }) {
  const encodedInviteSecretMessage = ByteEncoding.inviteSecretMessage.encode({
    projectKey,
    encryptionKey,
  })
  const ephemeralEncryptKeypair = boxKeypair()
  const encryptedMessage = encryptMessage(
    encodedInviteSecretMessage,
    ephemeralEncryptKeypair.publicKey,
    ephemeralEncryptKeypair.secretKey,
    joinRequest.identityPublicKey
  )
  const byteEncodedInvite = ByteEncoding.invite.encode({
    ephemeralPublicKey: ephemeralEncryptKeypair.publicKey,
    encryptedMessage,
  })
  return StringEncoding[encoding].encode(byteEncodedInvite)
}

/**
 * Decode and decrypt an invite secret message from a string-encoded invite. The
 * decrypted message includes the project key for the project the invite is for.
 *
 * @param {string} str Invite encoded as a string
 * @param {Buffer} identityPublicKey 32-byte signing public key for the device receiving the invite
 * @param {Buffer} identitySecretKey 32-byte signing secret key for the device receiving the invite
 * @param {Object} options
 * @param {StringEncoding} options.encoding Use base32 if using for an alphanumeric encoded QR Code (uppercase A-Z, 0-9), or base62 for a URL.
 * @returns {InviteSecretMessage} Decoded invite secret message
 */
function decodeInviteSecretMessage(
  str,
  identityPublicKey,
  identitySecretKey,
  { encoding }
) {
  // TODO: validate characters used in encoded string?
  const byteEncodedInvite = StringEncoding[encoding].decode(str)
  const { ephemeralPublicKey, encryptedMessage } =
    ByteEncoding.invite.decode(byteEncodedInvite)
  const decryptedMessage = decryptMessage(
    encryptedMessage,
    identityPublicKey,
    identitySecretKey,
    ephemeralPublicKey
  )
  return ByteEncoding.inviteSecretMessage.decode(decryptedMessage)
}
