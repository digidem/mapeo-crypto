import test from 'node:test'
import assert from 'node:assert/strict'
import * as ByteEncoding from './byte-encoding.js'
import crypto from 'crypto'
import cenc from 'compact-encoding'
import { compile, constant, header } from 'compact-encoding-struct'

const fixtures = {
  joinRequest: {
    identityPublicKey: crypto.randomBytes(32),
  },
  invite: {
    ephemeralPublicKey: crypto.randomBytes(32),
    encryptedMessage: crypto.randomBytes(64),
  },
  inviteSecretMessage: {
    projectKey: crypto.randomBytes(32),
  },
}

test('can encode and decode messages correctly', () => {
  for (const [structName, data] of Object.entries(fixtures)) {
    const encoded = ByteEncoding[structName].encode(data)
    const decoded = ByteEncoding[structName].decode(encoded)
    assert.deepEqual(decoded, data, structName)
  }
})

test('can encode and decode secret message with encryption key', () => {
  const data = {
    projectKey: crypto.randomBytes(32),
    encryptionKey: crypto.randomBytes(32),
  }
  const encoded = ByteEncoding.inviteSecretMessage.encode(data)
  const decoded = ByteEncoding.inviteSecretMessage.decode(encoded)
  assert.deepEqual(decoded, data)
})

test('trying to decode an invalid buffer throws', () => {
  // Fuzz test - try a bunch of random data
  for (let i = 0; i < 100; i++) {
    for (const [structName, data] of Object.entries(fixtures)) {
      const invalid = crypto.randomBytes(128)
      assert.throws(() => ByteEncoding[structName].decode(invalid), /invalid/i)
    }
  }
})

test('trying to decode a different version throws', () => {
  const version2Structs = {
    joinRequest: compile({
      version: header(constant(cenc.uint, 2)),
      type: header(constant(cenc.fixed(1), Buffer.from('J'))),
      foo: cenc.string,
    }),
    invite: compile({
      version: header(constant(cenc.uint, 2)),
      type: header(constant(cenc.fixed(1), Buffer.from('I'))),
      foo: cenc.string,
    }),
    inviteSecretMessage: compile({
      version: header(constant(cenc.uint, 2)),
      type: header(constant(cenc.fixed(1), Buffer.from('S'))),
      foo: cenc.string,
    }),
  }
  const version2Fixture = {
    foo: 'foo',
  }
  for (const [structName, struct] of Object.entries(version2Structs)) {
    const encoded = cenc.encode(struct, version2Fixture)
    assert.throws(
      () => ByteEncoding[structName].decode(encoded),
      /invalid version/i,
      structName
    )
  }
})

test('trying to decode a different type throws', () => {
  for (const [structName, data] of Object.entries(fixtures)) {
    const encoded = ByteEncoding[structName].encode(data)
    for (const otherStructName of Object.keys(fixtures)) {
      if (otherStructName === structName) continue
      assert.throws(
        () => ByteEncoding[otherStructName].decode(encoded),
        /expected type/i
      )
    }
  }
})
