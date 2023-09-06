// @ts-check
const { sign, verifySignature, projectKeyToPublicId } = require('./utils.js')

exports.KeyManager = require('./key-manager')
exports.sign = sign
exports.verifySignature = verifySignature
exports.projectKeyToPublicId = projectKeyToPublicId
