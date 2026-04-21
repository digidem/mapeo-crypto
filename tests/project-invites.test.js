// @ts-check
import test from 'node:test'
import assert from 'node:assert/strict'
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

test('can generate and decode invite', () => {
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
    assert.deepEqual(secretMessage, { projectKey })
  }
})

test('can generate and decode invite with encryption key', () => {
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
    assert.deepEqual(secretMessage, { projectKey, encryptionKey })
  }
})

test('can encode and decode join request', () => {
  for (const encoding of encodings) {
    const identityPublicKey = crypto.randomBytes(32)
    const joinRequest = { identityPublicKey }
    const encoded = encodeJoinRequest(joinRequest, { encoding })
    const decoded = decodeJoinRequest(encoded, { encoding })
    assert.deepEqual(decoded, joinRequest)
  }
})
