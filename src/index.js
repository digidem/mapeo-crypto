import { sign, verifySignature, keyToPublicId } from './utils.js'
import KeyManager from './key-manager.js'
import { deriveMasterKeyFromRootKey } from './lib/key-utils.js'

export {
  KeyManager,
  sign,
  verifySignature,
  keyToPublicId,
  deriveMasterKeyFromRootKey,
}
