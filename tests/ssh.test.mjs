/**
 * End-to-end tests for host/ssh.js + host/shell.js against the real mock SSH
 * server: password/key auth, TOFU fingerprints, exec semantics (stdout/stderr,
 * exit codes, truncation, timeout, abort), remoteHome/expandRemotePath,
 * buildCommand (prompt-driven sudo input) and the persistent shell.
 */

import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { after, before, test } from 'node:test'

import { buildCommand, expandRemotePath, remoteHome, upload, download } from '../host/ssh.js'
import { openShell } from '../host/shell.js'
import { createKnownHosts } from '../host/knownhosts.js'
import { createSshClient } from '../host/ssh.js'
import {
  cleanupTempDirs,
  createRig,
  hostInput,
  KEY_NO_PASS,
  KEY_PASSPHRASE,
  KEY_WITH_PASS,
  makeTempDir,
  MOCK_PASSWORD,
  quietLogger,
  startMockServer,
} from './helpers.mjs'

let mock
let rig
let ssh
let host

before(async () => {
  mock = await startMockServer()
  rig = createRig()
  ssh = rig.ssh
  host = hostInput(mock, { id: 'web-1', name: 'web-1', tags: ['web'], sudo: false })
})

after(async () => {
  await mock?.close()
  await rig?.dispose()
  cleanupTempDirs()
})

function endClient(client) {
  try {
    client?.end?.()
  } catch {
    /* already gone */
  }
}

async function withClient(fn, { secret = { password: MOCK_PASSWORD }, hostOverrides = {} } = {}) {
  const connection = await ssh.connect({ ...host, ...hostOverrides }, secret, { timeoutMs: 10000 })
  try {
    return await fn(connection.client, connection)
  } finally {
    endClient(connection.client)
  }
}

// --- authentication & TOFU ------------------------------------------------

test('ssh.connect: password auth works and TOFU records the fingerprint', async () => {
  const connection = await ssh.connect(host, { password: MOCK_PASSWORD }, { timeoutMs: 10000 })
  try {
    assert.equal(connection.hostKeyStatus, 'new')
    assert.equal(connection.keyType, 'ssh-ed25519')
    assert.equal(connection.fingerprint, mock.fingerprint)
    assert.equal(connection.banner, '')
    const recorded = await rig.knownHosts.find('127.0.0.1', mock.port)
    assert.ok(recorded, 'known_hosts entry should be created on first contact')
    assert.equal(recorded.fingerprint, mock.fingerprint)
    assert.equal(recorded.host, '127.0.0.1')
    assert.equal(recorded.port, mock.port)
  } finally {
    endClient(connection.client)
  }

  const again = await ssh.connect(host, { password: MOCK_PASSWORD }, { timeoutMs: 10000 })
  try {
    assert.equal(again.hostKeyStatus, 'known')
    assert.equal(again.fingerprint, mock.fingerprint)
  } finally {
    endClient(again.client)
  }
})

test('ssh.connect: private key auth by content (plain and passphrase protected)', async () => {
  await withClient(
    async (client) => {
      const result = await ssh.exec(client, { command: 'echo key-auth-ok' })
      assert.equal(result.code, 0)
      assert.equal(result.output, 'key-auth-ok\n')
    },
    { secret: { privateKey: KEY_NO_PASS }, hostOverrides: { id: 'key-host', name: 'key-host', auth: 'key' } },
  )

  await withClient(
    async (client) => {
      const result = await ssh.exec(client, { command: 'echo passphrase-ok' })
      assert.equal(result.output, 'passphrase-ok\n')
    },
    {
      secret: { privateKey: KEY_WITH_PASS, passphrase: KEY_PASSPHRASE },
      hostOverrides: { id: 'key-pass-host', name: 'key-pass-host', auth: 'key' },
    },
  )
})

test('ssh.connect: private key auth by keyPath', async () => {
  const keyPath = path.join(makeTempDir('rb-keypath-'), 'id_ed25519')
  fs.writeFileSync(keyPath, KEY_NO_PASS, { mode: 0o600 })
  await withClient(
    async (client) => {
      const result = await ssh.exec(client, { command: 'echo keypath-ok' })
      assert.equal(result.output, 'keypath-ok\n')
    },
    {
      secret: {},
      hostOverrides: { id: 'keypath-host', name: 'keypath-host', auth: 'key', keyPath },
    },
  )
})

test('ssh.connect: auth/secret failures carry documented error codes', async () => {
  await assert.rejects(
    ssh.connect(host, { password: 'definitely-wrong' }, { timeoutMs: 10000 }),
    (error) => {
      assert.equal(error.code, 'auth-failed')
      assert.match(error.message, /认证失败/)
      return true
    },
  )
  await assert.rejects(ssh.connect(host, {}, { timeoutMs: 10000 }), { code: 'missing-secret' })
  await assert.rejects(
    ssh.connect({ ...host, auth: 'key', keyPath: '' }, {}, { timeoutMs: 10000 }),
    { code: 'key-not-found' },
  )
  await assert.rejects(
    ssh.connect({ ...host, auth: 'key', keyPath: '/definitely/not/a/key' }, {}, { timeoutMs: 10000 }),
    { code: 'key-not-found' },
  )
})

test('ssh.connect: host-key-changed is reported with previous/new fingerprint details', async () => {
  const knownHosts = createKnownHosts({ filePath: path.join(makeTempDir('rb-kh2-'), 'known_hosts.json') })
  const client = createSshClient({ knownHosts, logger: quietLogger })
  const first = await client.connect(host, { password: MOCK_PASSWORD }, { timeoutMs: 10000 })
  endClient(first.client)

  const previousFingerprint = `SHA256:${'A'.repeat(43)}`
  await knownHosts.approve({
    host: host.host,
    port: host.port,
    keyType: 'ssh-ed25519',
    fingerprint: previousFingerprint,
  })

  await assert.rejects(client.connect(host, { password: MOCK_PASSWORD }, { timeoutMs: 10000 }), (error) => {
    assert.equal(error.code, 'host-key-changed')
    assert.equal(error.details.host, host.host)
    assert.equal(error.details.port, host.port)
    assert.equal(error.details.fingerprint, mock.fingerprint)
    assert.equal(error.details.previousFingerprint, previousFingerprint)
    assert.equal(error.details.keyType, 'ssh-ed25519')
    return true
  })

  // After the user approves the new fingerprint, connecting works again.
  await knownHosts.approve({
    host: host.host,
    port: host.port,
    keyType: 'ssh-ed25519',
    fingerprint: mock.fingerprint,
  })
  const afterApproval = await client.connect(host, { password: MOCK_PASSWORD }, { timeoutMs: 10000 })
  try {
    assert.equal(afterApproval.hostKeyStatus, 'known')
    assert.equal(afterApproval.fingerprint, mock.fingerprint)
  } finally {
    endClient(afterApproval.client)
  }
})

test('ssh.connect: a really rotated server host key triggers host-key-changed', async () => {
  const rotated = await startMockServer()
  const knownHosts = createKnownHosts({ filePath: path.join(makeTempDir('rb-kh3-'), 'known_hosts.json') })
  const client = createSshClient({ knownHosts, logger: quietLogger })
  const rotatedHost = hostInput(rotated, { id: 'rotated', name: 'rotated' })
  try {
    const firstFingerprint = rotated.fingerprint
    const first = await client.connect(rotatedHost, { password: MOCK_PASSWORD }, { timeoutMs: 10000 })
    endClient(first.client)
    assert.equal(first.fingerprint, firstFingerprint)

    await rotated.setHostKey(rotated.generateHostKey())
    const newFingerprint = rotated.fingerprint
    assert.notEqual(newFingerprint, firstFingerprint)

    await assert.rejects(client.connect(rotatedHost, { password: MOCK_PASSWORD }, { timeoutMs: 10000 }), (error) => {
      assert.equal(error.code, 'host-key-changed')
      assert.equal(error.details.fingerprint, newFingerprint)
      assert.equal(error.details.previousFingerprint, firstFingerprint)
      return true
    })

    await knownHosts.approve({
      host: rotatedHost.host,
      port: rotatedHost.port,
      keyType: 'ssh-ed25519',
      fingerprint: newFingerprint,
    })
    const approved = await client.connect(rotatedHost, { password: MOCK_PASSWORD }, { timeoutMs: 10000 })
    try {
      assert.equal(approved.hostKeyStatus, 'known')
      assert.equal(approved.fingerprint, newFingerprint)
    } finally {
      endClient(approved.client)
    }
  } finally {
    await rotated.close()
  }
})

// --- exec ------------------------------------------------------------------

test('ssh.exec: returns stdout, exit code and flags', async () => {
  await withClient(async (client) => {
    const result = await ssh.exec(client, { command: 'echo hello' })
    assert.equal(result.code, 0)
    assert.equal(result.signal, null)
    assert.equal(result.output, 'hello\n')
    assert.equal(result.truncated, false)
    assert.equal(result.timedOut, false)
    assert.equal(result.aborted, false)

    const failed = await ssh.exec(client, { command: 'exit 7' })
    assert.equal(failed.code, 7)
    assert.equal(failed.output, '')

    const withStderr = await ssh.exec(client, { command: 'echo out; echo err >&2; exit 3' })
    assert.equal(withStderr.code, 3)
    assert.equal(withStderr.output, 'out\n\n[stderr]\nerr\n')
  })
})

test('ssh.exec: caps oversized output with a truncation marker', async () => {
  await withClient(async (client) => {
    const result = await ssh.exec(client, {
      command: "head -c 20000 /dev/zero | tr '\\0' 'a'",
      maxOutputBytes: 1024,
    })
    assert.equal(result.code, 0)
    assert.equal(result.truncated, true)
    assert.ok(Buffer.byteLength(result.output) <= 1024, `output bytes: ${Buffer.byteLength(result.output)}`)
    assert.match(result.output, /输出过长/)
  })
})

test('ssh.exec: timeout resolves with timedOut=true and code null', async () => {
  await withClient(async (client) => {
    const startedAt = Date.now()
    const result = await ssh.exec(client, { command: 'sleep 5', timeoutMs: 400 })
    const elapsed = Date.now() - startedAt
    assert.equal(result.timedOut, true)
    assert.equal(result.aborted, false)
    assert.equal(result.code, null)
    assert.ok(elapsed < 4000, `elapsed: ${elapsed}ms`)
  })
})

test('ssh.exec: abort signal resolves with aborted=true and code null', async () => {
  await withClient(async (client) => {
    const controller = new AbortController()
    const pending = ssh.exec(client, { command: 'sleep 5', timeoutMs: 8000, signal: controller.signal })
    setTimeout(() => controller.abort(), 100)
    const result = await pending
    assert.equal(result.aborted, true)
    assert.equal(result.timedOut, false)
    assert.equal(result.code, null)
  })
})

test('ssh.exec: remoteHome and expandRemotePath resolve ~ against the remote HOME', async () => {
  await withClient(async (client) => {
    const home = await remoteHome(client)
    assert.equal(home, mock.homeDir)
    assert.equal(expandRemotePath('~', home), mock.homeDir)
    assert.equal(expandRemotePath('~/file.txt', home), `${mock.homeDir}/file.txt`)
    assert.equal(expandRemotePath('$HOME/file.txt', home), `${mock.homeDir}/file.txt`)
    assert.equal(expandRemotePath('/abs/file.txt', home), '/abs/file.txt')
    assert.equal(expandRemotePath('', home), '')
  })
})

test('ssh.buildCommand: quotes cwd and keeps sudo passwords out of argv', () => {
  assert.deepEqual(buildCommand({ command: 'echo hi' }), { remoteCommand: 'echo hi' })
  assert.deepEqual(buildCommand({ command: 'echo hi', cwd: '/tmp/a b' }), {
    remoteCommand: "cd '/tmp/a b' && (\necho hi\n)",
  })

  const sudo = buildCommand({ command: 'echo hi', sudo: true, sudoPassword: 'sudo-secret' })
  assert.equal(Object.keys(sudo).sort().join(','), 'remoteCommand,sudoInput')
  assert.ok(!sudo.remoteCommand.includes('sudo-secret'), 'entire command must exclude the password')
  assert.equal(sudo.sudoInput.password, 'sudo-secret')
  assert.match(sudo.sudoInput.prompt, /^__RB_SUDO_[0-9a-f]{48}__$/)
  assert.ok(sudo.remoteCommand.includes(sudo.sudoInput.prompt))
  assert.match(sudo.remoteCommand, /exec <\/dev\/null/)

  const combined = buildCommand({ command: 'echo hi', cwd: '/srv/app', sudo: true, sudoPassword: 'pw' })
  assert.match(combined.remoteCommand, /^cd '\/srv\/app' && \(\nsudo -S/)
  assert.ok(!combined.remoteCommand.includes('pw'))
  assert.equal(combined.sudoInput.password, 'pw')

  const quoted = buildCommand({ command: "echo 'quoted arg'", sudo: true, sudoPassword: 'pw' })
  assert.ok(quoted.remoteCommand.includes(`'\\''`), quoted.remoteCommand)

  assert.equal(buildCommand({ command: 'id', sudo: true }).sudoInput.password, '', 'NOPASSWD requires no configured password; reject only when sudo requests one')
  assert.throws(
    () => buildCommand({ command: 'id', sudo: true, sudoPassword: 'line1\nline2' }),
    { code: 'invalid-secret' },
  )
})

// --- persistent shell ------------------------------------------------------

test('shell: cd and export persist across run() calls, exit codes and stderr work', async () => {
  await withClient(async (client) => {
    const session = await openShell(client, { timeoutMs: 10000 })
    try {
      assert.equal(session.alive, true)
      const dir = path.join(mock.homeDir, 'persist')
      const started = await session.run(`mkdir -p "$HOME/persist" && cd "$HOME/persist" && pwd`)
      assert.equal(started.code, 0)
      assert.equal(started.output, `${dir}\n`)
      assert.equal(started.timedOut, false)

      const exported = await session.run('export RB_SHELL_TEST=42')
      assert.equal(exported.code, 0)
      assert.equal(exported.output, '')

      const echo = await session.run('echo "value=$RB_SHELL_TEST"; pwd')
      assert.equal(echo.code, 0)
      assert.equal(echo.output, `value=42\n${dir}\n`)

      const failed = await session.run('false')
      assert.equal(failed.code, 1)

      // Completion waits for both stream markers; stderr needs no timing workaround.
      const stderr = await session.run('echo oops >&2')
      assert.equal(stderr.code, 0)
      assert.match(stderr.output, /\[stderr\]\noops/)
    } finally {
      await session.close()
    }
    assert.equal(session.alive, false)
    await assert.rejects(session.run('echo nope'), { code: 'session-lost' })
  })
})

test('shell: timeout closes the session instead of desynchronising it', async () => {
  await withClient(async (client) => {
    const session = await openShell(client, { timeoutMs: 10000 })
    const result = await session.run('sleep 5', { timeoutMs: 300 })
    assert.equal(result.timedOut, true)
    assert.equal(result.code, null)
    assert.equal(session.alive, false)
    await assert.rejects(session.run('echo nope'), { code: 'session-lost' })
  })
})

// --- SFTP direct -----------------------------------------------------------

test('ssh.upload/download: file round-trip through SFTP', async () => {
  const localDir = makeTempDir('rb-sftp-')
  const source = path.join(localDir, 'source.txt')
  const payload = 'remote-bash direct sftp payload\n'.repeat(64)
  fs.writeFileSync(source, payload)

  await withClient(async (client) => {
    const uploadResult = await upload({ client, localPath: source, remotePath: `${mock.homeDir}/direct.txt` })
    assert.equal(uploadResult.bytes, Buffer.byteLength(payload))
    const cat = await ssh.exec(client, { command: 'cat "$HOME/direct.txt"' })
    assert.equal(cat.output, payload)

    const target = path.join(localDir, 'downloaded.txt')
    const downloadResult = await download({ client, remotePath: '~/direct.txt', localPath: target })
    assert.equal(downloadResult.bytes, Buffer.byteLength(payload))
    assert.equal(fs.readFileSync(target, 'utf8'), payload)
  })

  await assert.rejects(upload({ client: null, localPath: path.join(localDir, 'missing') }), {
    code: 'local-not-found',
  })
})

test('ssh.download: missing remote path raises remote-not-found', async () => {
  await withClient(async (client) => {
    await assert.rejects(
      download({ client, remotePath: '~/definitely-missing.txt', localPath: path.join(makeTempDir('rb-dl-'), 'x') }),
      { code: 'remote-not-found' },
    )
  })
})
