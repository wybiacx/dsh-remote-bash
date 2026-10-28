import assert from 'node:assert/strict'
import { createPrivateKey, createPublicKey, verify } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { after, test } from 'node:test'
import ssh2 from 'ssh2'
import { generateEd25519KeyPair } from './test-keys.mjs'
import { cleanupTempDirs, createRig, hostInput, makeTempDir, MOCK_PASSWORD, startMockServer } from './helpers.mjs'

after(cleanupTempDirs)

function leadingZeroKey() {
  // Public, synthetic test seed: counter 36 gives a public key beginning with 00.
  // Use RFC 8410 PKCS#8 encoding so this boundary never depends on random luck.
  const seed = Buffer.alloc(32)
  seed.writeUInt32BE(36, 28)
  return createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
    format: 'der', type: 'pkcs8',
  })
}

function parsePrivate(text) {
  const parsed = ssh2.utils.parseKey(text)
  assert.ok(!(parsed instanceof Error), parsed?.message)
  return Array.isArray(parsed) ? parsed[0] : parsed
}

test('test keys: leading-zero Ed25519 public bytes retain their full width and signatures', () => {
  const native = leadingZeroKey()
  const expected = Buffer.from(native.export({ format: 'jwk' }).x, 'base64url')
  assert.equal(expected.length, 32)
  assert.equal(expected[0], 0)
  const pair = generateEd25519KeyPair(native)
  const key = parsePrivate(pair.private)
  const blob = key.getPublicSSH()
  const offset = 4 + blob.readUInt32BE(0)
  assert.equal(blob.readUInt32BE(offset), 32)
  assert.deepEqual(blob.subarray(offset + 4), expected)
  assert.deepEqual(ssh2.utils.parseKey(pair.public).getPublicSSH(), blob)
  const message = Buffer.from('fixed-width Ed25519 regression')
  const signature = key.sign(message)
  assert.ok(Buffer.isBuffer(signature))
  assert.equal(verify(null, message, createPublicKey(native), signature), true)
})

test('test keys: OpenSSH independently reads a private key with a leading-zero public byte', () => {
  const pair = generateEd25519KeyPair(leadingZeroKey())
  const filename = path.join(makeTempDir('rb-key-format-'), 'synthetic-key')
  fs.writeFileSync(filename, pair.private, { mode: 0o600 })
  const publicKey = execFileSync('ssh-keygen', ['-y', '-f', filename], { encoding: 'utf8' })
  assert.equal(publicKey.trim().split(/\s+/).slice(0, 2).join(' '), pair.public)
})

test('test keys: the mock server authenticates with the deterministic leading-zero host key', async () => {
  const rig = createRig()
  let mock
  let client
  try {
    mock = await startMockServer({ hostKey: generateEd25519KeyPair(leadingZeroKey()) })
    const connected = await rig.ssh.connect(hostInput(mock), { password: MOCK_PASSWORD }, { timeoutMs: 10000 })
    client = connected.client
    assert.equal(connected.fingerprint, mock.fingerprint)
    const result = await rig.ssh.exec(client, { command: 'printf leading-zero-key-ok', timeoutMs: 10000 })
    assert.equal(result.code, 0)
    assert.equal(result.output, 'leading-zero-key-ok')
  } finally {
    client?.destroy()
    await mock?.close()
    await rig.dispose()
  }
})

test('test keys: fresh keys are distinct and invalid caller-provided host keys still fail', async () => {
  const first = generateEd25519KeyPair()
  const second = generateEd25519KeyPair()
  assert.notEqual(first.public, second.public)
  parsePrivate(first.private)
  parsePrivate(second.private)
  await assert.rejects(startMockServer({ hostKey: 'invalid-private-key' }), /Cannot parse host key/)
})
