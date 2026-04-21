// @ts-check
import t from 'tap'
import crypto from 'crypto'
import { encryptMessage, decryptMessage } from './invite-utils.js'
import { boxKeypair, signKeypair } from './key-utils.js'

t.test('can encrypt and decrypt message', (t) => {
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
  t.same(decrypted, message)
  t.end()
})

t.test('trying to encrypt invalid message throws', (t) => {
  const invalid = crypto.randomBytes(128)
  const senderKeypair = boxKeypair()
  const receiverKeypair = signKeypair()

  t.throws(() =>
    decryptMessage(
      invalid,
      receiverKeypair.publicKey,
      receiverKeypair.secretKey,
      senderKeypair.publicKey
    )
  )
  t.end()
})
