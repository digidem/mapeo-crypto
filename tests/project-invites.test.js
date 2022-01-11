// @ts-check
const { test } = require('tap')
const crypto = require('crypto')
const { boxKeypair, signKeypair } = require('../lib/key-utils')
const {
  generateInvite,
  decodeInviteSecretMessage,
  encodeJoinRequest,
  decodeJoinRequest,
} = require('../project-invites')

/** @type {Array<keyof typeof import('../lib/string-encoding')>} */
const encodings = ['base32', 'base62']

test('can generate and decode invite', (t) => {
  for (const encoding of encodings) {
    const projectKey = crypto.randomBytes(32)
    const receiverKeypair = signKeypair()
    const joinRequest = { identityPublicKey: receiverKeypair.publicKey }
    const invite = generateInvite(joinRequest, {
      projectKey,
      encoding,
    })
    const secretMessage = decodeInviteSecretMessage(
      invite,
      receiverKeypair.publicKey,
      receiverKeypair.secretKey,
      { encoding }
    )
    t.same(secretMessage, { projectKey })
  }
  t.end()
})

test('can generate and decode invite with encryption key', (t) => {
  for (const encoding of encodings) {
    const projectKey = crypto.randomBytes(32)
    const encryptionKey = crypto.randomBytes(32)
    const receiverKeypair = signKeypair()
    const joinRequest = { identityPublicKey: receiverKeypair.publicKey }
    const invite = generateInvite(joinRequest, {
      projectKey,
      encryptionKey,
      encoding,
    })
    const secretMessage = decodeInviteSecretMessage(
      invite,
      receiverKeypair.publicKey,
      receiverKeypair.secretKey,
      { encoding }
    )
    t.same(secretMessage, { projectKey, encryptionKey })
  }
  t.end()
})

test('can encode and decode join request', (t) => {
  for (const encoding of encodings) {
    const identityPublicKey = crypto.randomBytes(32)
    const joinRequest = { identityPublicKey }
    const encoded = encodeJoinRequest(joinRequest, { encoding })
    const decoded = decodeJoinRequest(encoded, { encoding })
    t.same(decoded, joinRequest)
  }
  t.end()
})
