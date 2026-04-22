import test from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'crypto'
import { encryptMessage, decryptMessage } from './invite-utils.js'
import { boxKeypair, signKeypair } from './key-utils.js'

test('can encrypt and decrypt message', () => {
  const message = crypto.randomBytes(128)
  const senderKeypair = boxKeypair()
  const receiverKeypair = signKeypair()
  const encrypted = encryptMessage(
    message,
    senderKeypair.publicKey,
    senderKeypair.secretKey,
    receiverKeypair.publicKey
  )
  const decrypted = decryptMessage(
    encrypted,
    receiverKeypair.publicKey,
    receiverKeypair.secretKey,
    senderKeypair.publicKey
  )
  assert.deepEqual(decrypted, message)
})

test('trying to encrypt invalid message throws', () => {
  const invalid = crypto.randomBytes(128)
  const senderKeypair = boxKeypair()
  const receiverKeypair = signKeypair()

  assert.throws(() =>
    decryptMessage(
      invalid,
      receiverKeypair.publicKey,
      receiverKeypair.secretKey,
      senderKeypair.publicKey
    )
  )
})
