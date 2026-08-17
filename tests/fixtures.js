import KeyManager from '../src/key-manager.js'

/**
 * @typedef {object} Device
 * @property {Buffer} rootKey
 * @property {Buffer} masterKey `deriveMasterKeyFromRootKey(rootKey)`
 * @property {string} backupCode `getIdentityBackupCode()` for `rootKey`
 */

/** @type {Device} */
export const DEVICE_A = {
  rootKey: Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'),
  masterKey: Buffer.from(
    'bed4350c496024724d50592eb2cd4f61b3333ea871c495f63a4f687aed67f82c',
    'hex',
  ),
  backupCode: 'M000G40R40M30E209185GR38E1WVKP',
}

/** @type {Device} */
export const DEVICE_B = {
  rootKey: Buffer.from('f0e0d0c0b0a09080706050403020100f', 'hex'),
  masterKey: Buffer.from(
    'a3cc3d3978074d908983144968ba6ac4655b3d1ff529b360854846c8c719891c',
    'hex',
  ),
  backupCode: 'MY3GD1G5GM2880W30A103080G1Z61G',
}

/**
 * Passing the pre-derived master key skips Argon2id, which otherwise costs
 * ~120ms per KeyManager and dominates the runtime of the whole suite. Tests
 * that are about the derivation itself construct their own instance.
 *
 * Key material goes in as plain Uint8Arrays, so every test built on this
 * exercises the widest type the API accepts. Buffer is a Uint8Array, so
 * passing one is covered by construction and needs no separate test.
 *
 * @param {Device} device
 * @returns {KeyManager}
 */
export function keyManagerFor({ rootKey, masterKey }) {
  return new KeyManager(u8(rootKey), { masterKey: u8(masterKey) })
}

/**
 * A plain Uint8Array over a copy of the same bytes - what a caller reading key
 * material off a native bridge or out of structured storage tends to hold.
 *
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
export function u8(bytes) {
  return Uint8Array.from(bytes)
}
