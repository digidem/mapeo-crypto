// @ts-check

// We are vendoring most of these cryptography functions, because any change to
// the algorythms would break the key derivation, and hence break Mapeo. We keep
// a lot more control over changes by vendoring these.
// See https://macwright.com/2021/03/11/vendor-by-default.html

const sodium = require('sodium-universal')
const assert = require('assert')

/** @typedef {{ publicKey: Buffer, secretKey: Buffer }} Keypair */

module.exports = {
  deriveMasterKeyFromRootKey,
  deriveNamedKey,
  signKeypair,
  boxKeypair,
  validateBoxKeypair,
  validateSignKeypair,
}

const PWHASH_OPSLIMIT = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
const PWHASH_MEMLIMIT = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
const PWHASH_ALG = sodium.crypto_pwhash_ALG_DEFAULT
const APPLICATION_NAMESPACE = Buffer.from('@mapeo/crypto')
const DEFAULT_TOKEN = Buffer.alloc(32, 0)

/**
 * Derive a 32-byte master key from the 18-byte root key. We compromise
 * entropy (16 bytes vs 32) for the sake of an root key that can be easily
 * written down (as 30 base-32 characters or 44 numerical digits). A 32-byte key
 * would be too long and more prone to error when transcribing. We could just
 * hash the root key, in the same way that derive-key hashes values, but by
 * using pwhash we increase security since it's more work to brute force how the
 * 16-bytes of entropy of the root key map to the 32-bytes of entropy of the
 * master key.
 *
 * @param {Buffer} rootKey 16-bytes root key
 * @returns {Buffer} 32-byte master key
 */
function deriveMasterKeyFromRootKey(rootKey) {
  assert(rootKey.length === 16, 'rootKey must be 16 bytes')
  const masterKey = sodium.sodium_malloc(32)

  sodium.crypto_pwhash(
    masterKey,
    // Zero-length password: all our entropy is in the salt
    Buffer.alloc(0),
    // The salt is the 16-byte root key
    rootKey,
    PWHASH_OPSLIMIT,
    PWHASH_MEMLIMIT,
    PWHASH_ALG
  )

  return masterKey
}

/**
 * Derive a named key from a 32 byte high-entropy master key. This can be
 * 32-bytes of cryptographically secure randomness, eg from a CSPRNG. Do NOT use
 * low entropy soruces such a passwords, passphrases or randomness from a
 * predictable RNG.
 *
 * Adapted from https://github.com/hyperdivision/derive-key/tree/v1.0.1 and the
 * implementation in corestore-next
 *
 * @param {Buffer} masterKey 32-byte high-entropy master key
 * @param {string} keyName Name of the key to derive
 * @param {Buffer} [token] Optional token (32-byte buffer) to use for key derivation, e.g. for namespacing keys
 * @returns {Buffer} 32-byte derived key
 */
function deriveNamedKey(masterKey, keyName, token) {
  assert(masterKey.length >= 32, 'masterKey must be at least 32 bytes')
  assert(!token || token.length >= 32, 'token must be at least 32 bytes')
  const output = Buffer.allocUnsafe(32)

  sodium.crypto_generichash_batch(
    output,
    [APPLICATION_NAMESPACE, token || DEFAULT_TOKEN, Buffer.from(keyName)],
    masterKey
  )

  return output
}

/**
 * Wrapper for sodium crypto_sign_keypair & crypto_sign_seed_keypair
 * @private
 *
 * @param {Buffer} [seed] Optional seed to deterministically generate the keypair
 */
function signKeypair(seed) {
  assert(!seed || seed.length >= 32, 'seed must be at least 32 bytes')
  const publicKey = Buffer.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = sodium.sodium_malloc(sodium.crypto_sign_SECRETKEYBYTES)

  if (seed) {
    sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  } else {
    sodium.crypto_sign_keypair(publicKey, secretKey)
  }

  return {
    publicKey,
    secretKey,
  }
}

/**
 * Wrapper for sodium crypto_box_keypair
 * @private
 */
function boxKeypair() {
  const publicKey = Buffer.allocUnsafe(sodium.crypto_box_PUBLICKEYBYTES)
  const secretKey = sodium.sodium_malloc(sodium.crypto_box_SECRETKEYBYTES)

  sodium.crypto_box_keypair(publicKey, secretKey)

  return {
    publicKey,
    secretKey,
  }
}

/** @param {Keypair} keypair */
function validateSignKeypair(keypair) {
  const pk = Buffer.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
  sodium.crypto_sign_ed25519_sk_to_pk(pk, keypair.secretKey)
  return pk.equals(keypair.publicKey)
}

/** @param {Keypair} keypair */
function validateBoxKeypair(keypair) {
  const pk = Buffer.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
  sodium.crypto_scalarmult_base(pk, keypair.secretKey)
  return pk.equals(keypair.publicKey)
}
