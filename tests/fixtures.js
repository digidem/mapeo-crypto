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
 * @param {Device} device
 * @returns {KeyManager}
 */
export function keyManagerFor({ rootKey, masterKey }) {
  return new KeyManager(rootKey, { masterKey })
}
