const { test } = require('tap')
const ByteEncoding = require('./byte-encoding')
const crypto = require('crypto')
const cenc = require('compact-encoding')
const { compile, constant, header } = require('compact-encoding-struct')

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

test('can encode and decode messages correctly', (t) => {
  for (const [structName, data] of Object.entries(fixtures)) {
    const encoded = ByteEncoding[structName].encode(data)
    const decoded = ByteEncoding[structName].decode(encoded)
    t.same(decoded, data, structName)
  }
  t.end()
})

test('can encode and decode secret message with encryption key', (t) => {
  const data = {
    projectKey: crypto.randomBytes(32),
    encryptionKey: crypto.randomBytes(32),
  }
  const encoded = ByteEncoding.inviteSecretMessage.encode(data)
  const decoded = ByteEncoding.inviteSecretMessage.decode(encoded)
  t.same(decoded, data)
  t.end()
})

test('trying to decode an invalid buffer throws', (t) => {
  // Fuzz test - try a bunch of random data
  for (let i = 0; i < 100; i++) {
    for (const [structName, data] of Object.entries(fixtures)) {
      const invalid = crypto.randomBytes(128)
      t.throws(() => ByteEncoding[structName].decode(invalid), /invalid/i)
    }
  }
  t.end()
})

test('trying to decode a different version throws', (t) => {
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
    t.throws(
      () => ByteEncoding[structName].decode(encoded),
      /invalid version/i,
      structName
    )
  }
  t.end()
})

test('trying to decode a different type throws', (t) => {
  for (const [structName, data] of Object.entries(fixtures)) {
    const encoded = ByteEncoding[structName].encode(data)
    for (const otherStructName of Object.keys(fixtures)) {
      if (otherStructName === structName) continue
      t.throws(
        () => ByteEncoding[otherStructName].decode(encoded),
        /expected type/i
      )
    }
  }
  t.end()
})
