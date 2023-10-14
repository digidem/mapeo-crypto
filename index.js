// @ts-check
const {
  sign,
  verifySignature,
  keyToPublicId,
} = require('./utils.js')

exports.KeyManager = require('./key-manager')
exports.sign = sign
exports.verifySignature = verifySignature
exports.keyToPublicId = keyToPublicId
