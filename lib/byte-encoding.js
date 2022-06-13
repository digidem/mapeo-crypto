// @ts-check
const cenc = require('compact-encoding')
const assert = require('assert')
const {
  compile,
  opt,
  constant,
  header,
  getHeader,
} = require('compact-encoding-struct')
const { ipv4Address } = require('compact-encoding-net')
const omitBy = require('lodash/omitBy')

const VERSIONS = {
  joinRequest: /** @type {const} */ (1),
  invite: /** @type {const} */ (1),
  inviteSecretMessage: /** @type {const} */ (1),
}

// Encode message types to help identify errors if messages are mixed (e.g.
// somehow we try to decode an invite as a join request). This also improves
// detection of invalid messages (because decoding the version from a random
// buffer often returns a valid value). There is always a chance however that a
// random buffer could contain a field that decodes as a message type, but the
// decoding will still fail after the header check.
const TYPES = {
  joinRequest: /** @type {const} */ ('J'),
  invite: /** @type {const} */ ('I'),
  inviteSecretMessage: /** @type {const} */ ('S'),
}

/**
 * @typedef {object} JoinRequest
 * @property {Buffer} identityPublicKey 32-byte public signing key (ed25519) that uniquely identifies the device
 * @property {{ host: string, port: number }} [host] Optional host ipv4 address and port to allow the admin to connect directly to the requester with the invite
 * @property {string} [name] Optional name that will be shown to the admin receiving the join request
 */

/**
 * @typedef {object} Invite
 * @property {Buffer} ephemeralPublicKey 32-byte public key
 * @property {Buffer} encryptedMessage Encrypted message as a buffer
 */

/**
 * @typedef {object} InviteSecretMessage
 * @property {Buffer} projectKey 32-byte project key
 * @property {Buffer} [encryptionKey] 32-byte encryption key
 */

/**
 * @typedef {object} BackupCode
 * @property {Buffer} rootKey 16-byte buffer - identity master key for device
 * @property {number} crc16 16-bit crc16 checksum of rootKey
 */

const STRUCTS = {}

STRUCTS.joinRequest = compile({
  version: header(constant(cenc.uint, VERSIONS.joinRequest)),
  type: header(constant(cenc.fixed(1), Buffer.from(TYPES.joinRequest))),
  identityPublicKey: cenc.fixed32,
  host: opt(ipv4Address),
  name: opt(cenc.string),
})

STRUCTS.invite = compile({
  version: header(constant(cenc.uint, VERSIONS.invite)),
  type: header(constant(cenc.fixed(1), Buffer.from(TYPES.invite))),
  ephemeralPublicKey: cenc.fixed32,
  encryptedMessage: cenc.buffer,
})

STRUCTS.inviteSecretMessage = compile({
  version: header(constant(cenc.uint, VERSIONS.inviteSecretMessage)),
  type: header(constant(cenc.fixed(1), Buffer.from(TYPES.inviteSecretMessage))),
  projectKey: cenc.fixed32,
  encryptionKey: opt(cenc.fixed32),
})

/**
 * @param {keyof typeof STRUCTS} structName
 * @param {Omit<JoinRequest | Invite | InviteSecretMessage, 'version'>} data
 * @returns {Buffer}
 */
function encode(structName, data) {
  return cenc.encode(STRUCTS[structName], data)
}

/**
 * @template {keyof typeof STRUCTS} T
 * @param {T} structName
 * @param {Buffer} buf
 * @returns {T extends 'joinRequest' ? JoinRequest : T extends 'invite' ? Invite : T extends 'inviteSecretMessage' ? InviteSecretMessage : never}
 */
function decode(structName, buf) {
  const expectedVersion = VERSIONS[structName]
  const expectedType = TYPES[structName]
  let version
  let messageType
  try {
    const header = getHeader(buf, { version: cenc.uint, type: cenc.fixed(1) })
    version = header.version
    messageType = header.type.toString()
  } catch (err) {
    throw new Error(`Invalid buffer: ${err.message}`)
  }
  if (messageType !== expectedType) {
    throw new Error(
      `Invalid buffer: Expected type ${expectedType}, got ${messageType}`
    )
  }
  if (version !== expectedVersion) {
    throw new Error(
      `Invalid Version: Expected version ${expectedVersion}, got ${version}`
    )
  }
  const struct = STRUCTS[structName]
  const { version: _v, type: _t, ...decoded } = cenc.decode(struct, buf)
  // Optional fields are decoded as null if they are not present in the buffer,
  // so we omit them from the returned object. NOTE: this might break things if
  // we start expecting null values on the messages
  return /** @type {any} */ (omitBy(decoded, (v) => v === null))
}

module.exports = {
  joinRequest: {
    /** @param {JoinRequest} joinRequest */
    encode(joinRequest) {
      return encode('joinRequest', joinRequest)
    },
    /** @param {Buffer} buf */
    decode(buf) {
      return decode('joinRequest', buf)
    },
  },
  invite: {
    /** @type {(invite: Invite) => Buffer} */
    encode(invite) {
      return encode('invite', invite)
    },
    /** @type {(buf: Buffer) => Invite} */
    decode(buf) {
      return decode('invite', buf)
    },
  },
  inviteSecretMessage: {
    /** @type {(inviteSecretMessage: InviteSecretMessage) => Buffer} */
    encode(inviteSecretMessage) {
      return encode('inviteSecretMessage', inviteSecretMessage)
    },
    /** @type {(buf: Buffer) => InviteSecretMessage} */
    decode(buf) {
      return decode('inviteSecretMessage', buf)
    },
  },
  backupCode: {
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
  },
}
