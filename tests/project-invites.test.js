// @ts-check
import t from 'tap'
import crypto from 'crypto'
import { boxKeypair, signKeypair } from '../lib/key-utils.js'
import {
  generateInvite,
  decodeInviteSecretMessage,
  encodeJoinRequest,
  decodeJoinRequest,
} from '../project-invites.js'

/** @type {Array<keyof typeof import('../lib/string-encoding')>} */
const encodings = ['base32', 'base62']

t.test('can generate and decode invite', (t) => {
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

t.test('can generate and decode invite with encryption key', (t) => {
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

t.test('can encode and decode join request', (t) => {
  for (const encoding of encodings) {
    const identityPublicKey = crypto.randomBytes(32)
    const joinRequest = { identityPublicKey }
    const encoded = encodeJoinRequest(joinRequest, { encoding })
    const decoded = decodeJoinRequest(encoded, { encoding })
    t.same(decoded, joinRequest)
  }
  t.end()
})
