/** Protocol regressions: real localhost SSH + real Bash, and deterministic stalled SFTP fixtures.
 * Successful wire operations allow 10s because the full suite starts several crypto-heavy SSH fixtures concurrently.
 * Deadline/cancellation regressions below keep their deliberately short budgets.
 */
import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import { EventEmitter } from 'node:events'
import { after, before, test } from 'node:test'
import { buildCommand, createSudoResponder, download, execChannel, remoteHome, remoteStat, upload } from '../host/ssh.js'
import { openShell } from '../host/shell.js'
import { createSessionManager } from '../host/sessions.js'
import { cleanupTempDirs, createRig, hostInput, makeTempDir, MOCK_PASSWORD, MOCK_SUDO_PASSWORD, startMockServer, waitUntil } from './helpers.mjs'

let mock, rig, host
before(async () => {
  mock = await startMockServer()
  rig = createRig()
  host = hostInput(mock, { id: 'regression', name: 'regression' })
})
after(async () => { await mock?.close(); await rig?.dispose(); cleanupTempDirs() })
async function connected(fn) {
  const { client } = await rig.ssh.connect(host, { password: MOCK_PASSWORD })
  try { return await fn(client) } finally { client.destroy() }
}

for (const mode of ['password', 'cached', 'nopasswd']) {
  test(`sudo ${mode}: exec and persistent shell isolate password from cat/read`, async () => connected(async (client) => {
    const built = buildCommand({ command: 'cat; read -r line; printf "done\\n"', sudo: true, sudoPassword: MOCK_SUDO_PASSWORD })
    assert.ok(!built.remoteCommand.includes(MOCK_SUDO_PASSWORD))
    const result = await execChannel(client, { command: `RB_TEST_SUDO_MODE=${mode} ${built.remoteCommand}`, sudoInput: built.sudoInput, timeoutMs: 10000 })
    assert.equal(result.code, 0)
    assert.equal(result.output, 'done\n')
    const shell = await openShell(client)
    try {
      await shell.run(`export RB_TEST_SUDO_MODE=${mode}`)
      const elevated = await shell.run(built.remoteCommand, { sudoInput: built.sudoInput, timeoutMs: 10000 })
      assert.equal(elevated.code, 0)
      assert.equal(elevated.output, 'done\n')
      assert.equal((await shell.run('printf "still-synchronized\\n"')).output, 'still-synchronized\n')
    } finally { await shell.close() }
  }))
}

test('sudo without configured password permits NOPASSWD but fails on an actual authentication prompt', async () => connected(async (client) => {
  const built = buildCommand({ command: 'cat; printf no-password-needed', sudo: true })
  const result = await execChannel(client, { command: `RB_TEST_SUDO_MODE=nopasswd ${built.remoteCommand}`, sudoInput: built.sudoInput, timeoutMs: 10000 })
  assert.equal(result.code, 0)
  assert.equal(result.output, 'no-password-needed')
  await assert.rejects(execChannel(client, { command: built.remoteCommand, sudoInput: built.sudoInput, timeoutMs: 10000 }), { code: 'sudo-password-missing' })
  const shell = await openShell(client)
  try {
    await shell.run('export RB_TEST_SUDO_MODE=nopasswd')
    assert.equal((await shell.run(built.remoteCommand, { sudoInput: built.sudoInput, timeoutMs: 10000 })).output, 'no-password-needed')
  } finally { await shell.close() }
}))

test('sudo: wrong password fails and never appears in returned output', async () => connected(async (client) => {
  const built = buildCommand({ command: 'echo should-not-run', sudo: true, sudoPassword: 'wrong-review-password' })
  const result = await execChannel(client, { command: built.remoteCommand, sudoInput: built.sudoInput, timeoutMs: 10000 })
  assert.equal(result.code, 1)
  assert.ok(!result.output.includes('wrong-review-password'))
  assert.ok(!result.output.includes('should-not-run'))
}))

test('sudo responder handles split prompts and sends one secret only', () => {
  const sent = [], output = [], errors = []
  const input = { prompt: '__TEST_RANDOM_PROMPT__', password: 'synthetic' }
  const responder = createSudoResponder(input, (text) => sent.push(text), (data) => output.push(Buffer.from(data)), (error) => errors.push(error))
  for (const byte of Buffer.from(`warning\n${input.prompt}after\n`)) responder.push(Buffer.from([byte]))
  responder.finish()
  assert.deepEqual(sent, ['synthetic\n'])
  assert.equal(Buffer.concat(output).toString(), 'warning\nafter\n')
  responder.push(Buffer.from(input.prompt))
  assert.equal(sent.length, 1)
  assert.equal(errors[0].code, 'sudo-auth-failed')
})

test('shell never requests PTY; stdin readers cannot consume frames and cd/export persist', async () => connected(async (client) => {
  const shell = await openShell(client)
  try {
    assert.equal(mock.ptyRequests, 0)
    const read = await shell.run('read -r value; printf "read=%s\\n" "$?"; cat; export AFTER_READ=yes')
    assert.equal(read.code, 0)
    assert.equal(read.output, 'read=1\n')
    const multiline = await shell.run('for i in 1 2; do\n printf "item=%s\\n" "$i"\ndone\ncd "$HOME"')
    assert.equal(multiline.output, 'item=1\nitem=2\n')
    assert.equal((await shell.run('printf "%s\\n" "$AFTER_READ"; pwd')).output, `yes\n${mock.homeDir}\n`)
    for (let i = 0; i < 6; i += 1) {
      const result = await shell.run(`printf 'out-${i}'; printf 'err-${i}' >&2`)
      assert.equal(result.output, `out-${i}\n[stderr]\nerr-${i}`)
    }
  } finally { await shell.close() }
}))

test('shell bounds continuous stderr before completion and discards idle stderr', async () => connected(async (client) => {
  const shell = await openShell(client)
  try {
    const resultPromise = shell.run('head -c 8388608 /dev/zero >&2; sleep 0.3', { maxOutputBytes: 1024 })
    await waitUntil(() => {
      const reader = shell.active?.stderrReader
      return reader && reader.collector.total + reader.pending.length >= 8388608
    })
    const reader = shell.active.stderrReader
    assert.ok(reader.pending.length < reader.end.length, 'only a possible split marker suffix remains outside the collector')
    const collector = reader.collector
    assert.ok(collector.headLength <= 1024)
    assert.ok(collector.tailLength <= 512)
    const result = await resultPromise
    assert.equal(result.code, 0)
    assert.equal(result.truncated, true)
    assert.ok(Buffer.byteLength(result.output) <= 1024)
    shell.channel.stderr.emit('data', Buffer.alloc(1024 * 1024))
    assert.equal(shell.active, null)
    assert.equal((await shell.run('printf next')).output, 'next')
  } finally { await shell.close() }
}))

test('shell active abort closes channel; queued abort and failed validation never execute', async () => connected(async (client) => {
  const shell = await openShell(client)
  const queueAbort = new AbortController()
  const first = shell.run('sleep 0.1; printf first')
  const queued = shell.run('export MUST_NOT_RUN=yes', { signal: queueAbort.signal })
  const rejected = assert.rejects(queued, { code: 'aborted' })
  queueAbort.abort()
  await rejected
  assert.equal((await first).output, 'first')
  assert.equal((await shell.run('printf "%s" "${MUST_NOT_RUN:-no}"')).output, 'no')
  await assert.rejects(shell.run('echo forbidden', { validate: async () => { throw Object.assign(new Error('changed'), { code: 'target-changed' }) } }), { code: 'target-changed' })
  const activeAbort = new AbortController()
  const running = shell.run('sleep 5; echo forbidden', { signal: activeAbort.signal })
  setTimeout(() => activeAbort.abort(), 30)
  const result = await running
  assert.equal(result.aborted, true)
  assert.equal(result.code, null)
  assert.equal(shell.alive, false)
  assert.ok(!result.output.includes('forbidden'))
}))

test('exec closes a late channel after cancellation and pre-aborted calls report aborted', async () => {
  let callback, destroyed = false
  const controller = new AbortController()
  const pending = execChannel({ exec(_command, cb) { callback = cb } }, { command: 'echo test', signal: controller.signal })
  controller.abort()
  assert.equal((await pending).aborted, true)
  callback(null, { destroy() { destroyed = true } })
  assert.equal(destroyed, true)
  const already = await execChannel({ exec() { assert.fail('must not execute') } }, { command: 'true', signal: controller.signal })
  assert.equal(already.aborted, true)
})

test('exec never sends a password in response to a prompt arriving after cancellation', async () => {
  const channel = Object.assign(new EventEmitter(), { stderr: new EventEmitter(), close() {}, write() { assert.fail('cancelled call must not send a secret') } })
  const controller = new AbortController()
  const sudoInput = { prompt: '__LATE_PROMPT__', password: 'synthetic' }
  const pending = execChannel({ exec(_command, cb) { cb(null, channel) } }, { command: 'sudo dummy', sudoInput, signal: controller.signal })
  controller.abort()
  assert.equal((await pending).aborted, true)
  channel.stderr.emit('data', Buffer.from(sudoInput.prompt))
})

test('shell open cancellation closes a channel that arrives late', async () => {
  const controller = new AbortController()
  let callback, destroyed = false
  const pending = openShell({ shell(pty, cb) { assert.equal(pty, false); callback = cb } }, { signal: controller.signal })
  const rejected = assert.rejects(pending, { code: 'aborted' })
  controller.abort()
  await rejected
  callback(null, { destroy() { destroyed = true } })
  assert.equal(destroyed, true)
})

test('sessions share first connection, preserve queued state and never sweep busy work', async () => {
  const manager = createSessionManager({ ssh: rig.ssh, config: { sessionIdleMinutes: 1 } })
  const options = { agentId: 'review', label: 'shared', host, secret: { password: MOCK_PASSWORD } }
  const before = mock.connectionCount
  try {
    const one = manager.run({ ...options, command: 'export FIRST=one; sleep 0.05' })
    const two = manager.run({ ...options, command: 'printf "%s" "$FIRST"' })
    assert.equal((await one).code, 0)
    assert.equal((await two).output, 'one')
    assert.equal(mock.connectionCount - before, 1)
    const busy = manager.run({ ...options, command: 'sleep 0.1; printf busy' })
    manager.sweepIdle(Date.now() + 120000)
    assert.equal((await busy).output, 'busy')
    manager.sweepIdle(Date.now() + 120000)
    assert.equal(manager.size(), 0)
  } finally { manager.dispose() }
})

test('session revision/credential rotation and rejected validation cannot reuse old authentication', async () => {
  const manager = createSessionManager({ ssh: rig.ssh, config: {} })
  const options = { agentId: 'review', label: 'rotate', host: { ...host, revision: 1, credentialRef: 'old' }, secret: { password: MOCK_PASSWORD } }
  try {
    await manager.run({ ...options, command: 'export OLD_SESSION=yes' })
    const result = await manager.run({ ...options, host: { ...host, revision: 2, credentialRef: 'new' }, command: 'printf "%s" "${OLD_SESSION:-no}"' })
    assert.equal(result.output, 'no')
    await assert.rejects(manager.run({ ...options, command: 'echo forbidden', validate: async () => { throw Object.assign(new Error('changed'), { code: 'target-changed' }) } }), { code: 'target-changed' })
    assert.equal(manager.size(), 0, 'validation failure must retire the old authenticated connection')
  } finally { manager.dispose() }
})

test('cancelling one creation waiter does not cancel another waiter sharing that connection', async () => {
  let release
  const manager = createSessionManager({ ssh: { connect: (...args) => new Promise((resolve, reject) => { release = () => rig.ssh.connect(...args).then(resolve, reject) }) }, config: {} })
  const options = { agentId: 'review', label: 'pending', host, secret: { password: MOCK_PASSWORD } }
  const controller = new AbortController()
  const cancelled = manager.run({ ...options, command: 'echo cancelled', signal: controller.signal })
  const rejected = assert.rejects(cancelled, { code: 'aborted' })
  const surviving = manager.run({ ...options, command: 'printf survivor' })
  controller.abort()
  await rejected
  release()
  try {
    assert.equal((await surviving).output, 'survivor')
    assert.equal(manager.size(), 1)
  } finally { manager.dispose() }
})

test('sessions closeHost invalidates in-flight creation and cannot resurrect old generation', async () => {
  let release
  let destroyed = 0
  const manager = createSessionManager({ ssh: { connect: () => new Promise((resolve) => { release = resolve }) }, config: {} })
  const pending = manager.run({ agentId: 'a', label: 'x', host, secret: {}, command: 'true' })
  const rejected = assert.rejects(pending, { code: 'session-closed' })
  assert.equal(await manager.closeHost(host.id), 1)
  release({ client: { destroy() { destroyed += 1 }, shell() { assert.fail('closed creation must not open shell') } } })
  await rejected
  assert.equal(destroyed, 1)
  assert.equal(manager.size(), 0)
  manager.dispose()
})

test('closing an old pending generation cannot remove its replacement', async () => {
  const releases = []
  const manager = createSessionManager({ ssh: { connect: (...args) => new Promise((resolve, reject) => releases.push(() => rig.ssh.connect(...args).then(resolve, reject))) }, config: {} })
  const options = { agentId: 'a', label: 'generation', host, secret: { password: MOCK_PASSWORD } }
  const first = manager.run({ ...options, command: 'echo old' })
  const failed = assert.rejects(first, (error) => error.code === 'aborted' || error.code === 'session-closed')
  await manager.closeHost(host.id)
  const second = manager.run({ ...options, command: 'printf replacement' })
  releases[0]()
  await failed
  releases[1]()
  try {
    assert.equal((await second).output, 'replacement')
    assert.equal(manager.size(), 1)
  } finally { manager.dispose() }
})

test('session capacity includes pending connections and never evicts active work', async () => {
  let connections = 0
  const manager = createSessionManager({ ssh: { connect(_host, _secret, { signal }) {
    connections += 1
    return new Promise((_, reject) => signal.addEventListener('abort', () => reject(Object.assign(new Error('closed'), { code: 'aborted' })), { once: true }))
  } }, config: {} })
  const running = Array.from({ length: 64 }, (_, i) => manager.run({ agentId: 'cap', label: `session-${i}`, host, secret: {}, command: 'true' }))
  const settled = Promise.allSettled(running)
  await assert.rejects(manager.run({ agentId: 'cap', label: 'extra', host, secret: {}, command: 'true' }), { code: 'session-limit' })
  assert.equal(connections, 64)
  manager.dispose()
  assert.ok((await settled).every((entry) => entry.status === 'rejected'))
  assert.equal(manager.size(), 0)
})

const fileStats = (size = 3) => ({ size, isFile: () => true, isDirectory: () => false, isSymbolicLink: () => false })
const dirStats = () => ({ size: 0, isFile: () => false, isDirectory: () => true, isSymbolicLink: () => false })
function sftpClient(overrides = {}) {
  const sftp = Object.assign(new EventEmitter(), {
    closed: false,
    destroy() { this.closed = true },
    lstat(_target, cb) { cb(null, fileStats()) },
    ...overrides,
  })
  return { sftp, client: { sftp(cb) { cb(null, sftp) } } }
}

test('download rejects malicious filenames before initiating a local write', async () => {
  const root = makeTempDir('rb-path-regression-')
  for (const filename of ['../outside', 'sub/../../outside', '/absolute', 'C:\\outside', 'sub\\outside', 'bad\0name']) {
    const fixture = sftpClient({ lstat(_p, cb) { cb(null, dirStats()) }, readdir(_p, cb) { cb(null, [{ filename, attrs: fileStats() }]) }, fastGet() { assert.fail('must not download unsafe entry') } })
    await assert.rejects(download({ client: fixture.client, remotePath: '/remote', localPath: root }), { code: 'unsafe-path' })
    assert.equal(fixture.sftp.closed, true)
  }
  assert.deepEqual(await fs.readdir(root), [])
})

test('download rejects existing local links and remote symlinks', async () => {
  const root = makeTempDir('rb-link-regression-')
  const outside = path.join(root, 'outside')
  const chosen = path.join(root, 'chosen')
  await fs.mkdir(outside)
  await fs.mkdir(chosen)
  await fs.symlink(outside, path.join(chosen, 'sub'))
  const fixture = sftpClient({ lstat(_p, cb) { cb(null, dirStats()) }, readdir(_p, cb) { cb(null, [{ filename: 'sub', attrs: dirStats() }]) }, fastGet() { assert.fail('must reject link') } })
  await assert.rejects(download({ client: fixture.client, remotePath: '/remote', localPath: chosen }), { code: 'unsafe-path' })
  const link = sftpClient({ lstat(_p, cb) { cb(null, { ...fileStats(), isSymbolicLink: () => true }) } })
  await assert.rejects(download({ client: link.client, remotePath: '/link', localPath: path.join(root, 'file') }), { code: 'unsafe-path' })
})

test('real SFTP lstat rejects a remote symlink instead of silently following it', async () => connected(async (client) => {
  const target = path.join(mock.homeDir, 'link-target')
  const link = path.join(mock.homeDir, 'remote-link')
  await fs.writeFile(target, 'private remote contents')
  await fs.symlink(target, link)
  const root = makeTempDir('rb-wire-link-')
  await assert.rejects(download({ client, remotePath: link, localPath: path.join(root, 'output') }), { code: 'unsafe-path' })
  assert.deepEqual(await fs.readdir(root), [])
}))

test('download failure preserves original file and cleans temporary staging', async () => {
  const root = makeTempDir('rb-atomic-regression-')
  const target = path.join(root, 'original')
  await fs.writeFile(target, 'original contents')
  const fixture = sftpClient({ fastGet(_remote, local, _opts, cb) {
    fs.writeFile(local, 'partial').then(() => cb(Object.assign(new Error('interrupted'), { code: 'sftp-failed' })), cb)
  } })
  await assert.rejects(download({ client: fixture.client, remotePath: '/file', localPath: target }), { code: 'sftp-failed' })
  assert.equal(await fs.readFile(target, 'utf8'), 'original contents')
  assert.deepEqual(await fs.readdir(root), ['original'])
})

for (const phase of ['open', 'lstat', 'readdir', 'fastGet']) {
  test(`SFTP deadline and abort cover stalled ${phase}`, async () => {
    const root = makeTempDir('rb-stall-regression-')
    for (const cancel of [false, true]) {
      const fixture = sftpClient({
        lstat(_p, cb) { if (phase !== 'lstat') cb(null, phase === 'readdir' ? dirStats() : fileStats()) },
        readdir() {}, fastGet() {},
      })
      let late
      if (phase === 'open') fixture.client.sftp = (cb) => { late = cb }
      const controller = new AbortController()
      const pending = download({ client: fixture.client, remotePath: '/file', localPath: path.join(root, cancel ? 'abort' : 'timeout'), timeoutMs: cancel ? 2000 : 30, signal: controller.signal })
      const assertion = assert.rejects(pending, { code: cancel ? 'aborted' : 'timeout' })
      const timer = cancel ? setTimeout(() => controller.abort(), 30) : null
      await assertion
      if (timer) clearTimeout(timer)
      if (late) late(null, fixture.sftp)
      assert.equal(fixture.sftp.closed, true)
      assert.ok(!(await fs.readdir(root)).some((name) => name.startsWith('.rb-download-')))
    }
  })
}

test('SFTP upload mkdir and remoteStat share metadata deadline', async () => {
  const root = makeTempDir('rb-upload-timeout-')
  const source = path.join(root, 'source')
  await fs.writeFile(source, 'source')
  const fixture = sftpClient({
    lstat(target, cb) { if (target === '/new') cb(Object.assign(new Error('missing'), { code: 2 })); else cb(null, dirStats()) },
    mkdir() {},
  })
  await assert.rejects(upload({ client: fixture.client, localPath: source, remotePath: '/new/file', timeoutMs: 30 }), { code: 'timeout' })
  assert.equal(fixture.sftp.closed, true)
  const metadata = sftpClient({ lstat() {} })
  await assert.rejects(remoteStat(metadata.client, '/missing', { timeoutMs: 30 }), { code: 'timeout' })
  assert.equal(metadata.sftp.closed, true)
  await assert.rejects(remoteHome({}, { deadline: Date.now() - 1 }), { code: 'timeout' })
})
