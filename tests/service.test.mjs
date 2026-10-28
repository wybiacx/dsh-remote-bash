/**
 * End-to-end service tests (host/service.js): inventory/credentials through the
 * service, target resolution, single & multi-host exec with failure isolation,
 * timeout/abort, persistent sessions, sudo, SFTP file/directory transfers and
 * the fingerprint TOFU/approve flow.
 */

import assert from 'node:assert/strict'
import fs from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import { after, before, test } from 'node:test'

import {
  cleanupTempDirs,
  createRig,
  KEY_NO_PASS,
  makeTempDir,
  MOCK_PASSWORD,
  MOCK_SUDO_PASSWORD,
  saveMockHost,
  startMockServer,
} from './helpers.mjs'

const WEB = 'web-1'
const DB = 'db-1'
const BROKEN = 'broken-1'
const SUDO_WRONG = 'sudo-wrong'
const KEY_HOST = 'key-1'
const BOGUS_FINGERPRINT = `SHA256:${'B'.repeat(43)}`

let mock
let rig
let closedPort
let hostCount
let hostIds
const idOf = (name) => hostIds[name]

function findClosedPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      server.close(() => resolve(port))
    })
  })
}

before(async () => {
  mock = await startMockServer()
  rig = createRig()
  closedPort = await findClosedPort()

  await saveMockHost(rig, mock, { name: WEB, tags: ['web', 'prod'] })
  await saveMockHost(rig, mock, { name: DB, tags: ['db', 'prod'] })
  await rig.service.saveHost({
    name: BROKEN,
    host: '127.0.0.1',
    port: closedPort,
    username: 'tester',
    auth: 'password',
    tags: [],
    secret: { password: MOCK_PASSWORD },
  })
  await saveMockHost(rig, mock, { name: SUDO_WRONG, tags: [] }, { sudoPassword: 'wrong-sudo' })
  await rig.service.saveHost({
    name: KEY_HOST,
    host: '127.0.0.1',
    port: mock.port,
    username: 'tester',
    auth: 'key',
    keyPath: '',
    tags: [],
    secret: { privateKey: KEY_NO_PASS },
  })
  const hosts = (await rig.service.state()).hosts
  hostCount = hosts.length
  hostIds = Object.fromEntries(hosts.map((host) => [host.name, host.id]))
})

after(async () => {
  await mock?.close()
  await rig?.dispose()
  cleanupTempDirs()
})

function hostResult(result, hostId) {
  const entry = result.hosts.find((host) => host.hostId === (hostIds[hostId] || hostId))
  assert.ok(entry, `result has no host ${hostId}: ${JSON.stringify(result.hosts, null, 2)}`)
  return entry
}

// --- state / inventory -----------------------------------------------------

test('service.state: settings, hosts + secret flags, groups, no secrets on disk', async () => {
  const state = await rig.service.state()
  assert.equal(state.settings.dataDir, rig.root)
  assert.equal(state.settings.approvalMode, 'dangerous')
  assert.equal(state.settings.defaultTimeoutSec, 60)
  assert.equal(state.settings.maxParallelHosts, 8)
  assert.equal(state.settings.maxOutputBytes, 32768)
  assert.equal(state.settings.sessionIdleMinutes, 30)
  assert.equal(state.credentialsAvailable, true)
  assert.equal(state.hosts.length, hostCount)
  assert.equal(hostCount, 5)

  const web = state.hosts.find((host) => host.id === idOf(WEB))
  assert.equal(web.username, 'tester')
  assert.equal(web.port, mock.port)
  assert.deepEqual(web.tags, ['web', 'prod'])
  assert.equal(web.secret.available, true)
  assert.equal(web.secret.configured, true)
  assert.equal(web.secret.fields.password, true)
  assert.equal(web.secret.fields.sudoPassword, true)
  assert.equal(web.secret.fields.privateKey, false)

  const keyHost = state.hosts.find((host) => host.id === idOf(KEY_HOST))
  assert.equal(keyHost.auth, 'key')
  assert.equal(keyHost.secret.fields.privateKey, true)
  assert.equal(keyHost.secret.fields.password, false)

  assert.deepEqual(state.groups, [
    { tag: 'db', hostIds: [idOf(DB)] },
    { tag: 'prod', hostIds: [idOf(WEB), idOf(DB)] },
    { tag: 'web', hostIds: [idOf(WEB)] },
  ])
  assert.deepEqual(state.knownHosts, [])
  assert.deepEqual(state.sessions, [])

  const inventoryText = fs.readFileSync(rig.paths.inventoryFile, 'utf8')
  for (const secret of [MOCK_PASSWORD, MOCK_SUDO_PASSWORD, 'wrong-sudo', KEY_NO_PASS.slice(0, 40)]) {
    assert.ok(!inventoryText.includes(secret), 'inventory.json must not contain secrets')
  }
  assert.equal(fs.statSync(rig.paths.inventoryFile).mode & 0o777, 0o600)
})

test('service.saveHost: validation + credential write/clear lifecycle', async () => {
  await assert.rejects(
    rig.service.saveHost({ name: WEB, host: '127.0.0.1', username: 'tester', auth: 'password' }),
    { code: 'duplicate-name' },
  )
  await assert.rejects(
    rig.service.saveHost({ name: 'bad', host: 'not a host', username: 'tester', auth: 'password' }),
    { code: 'invalid-host' },
  )

  const saved = await rig.service.saveHost({
    name: 'temp-host',
    host: '127.0.0.1',
    port: mock.port,
    username: 'tester',
    auth: 'password',
    tags: ['temp'],
    secret: { password: 'temp-pw' },
  })
  assert.match(saved.host.id, /^temp-host-/)
  assert.equal(saved.host.secret.fields.password, true)
  assert.ok(saved.state.hosts.some((host) => host.id === saved.host.id))
  const tempRef = (await rig.inventory.get(saved.host.id)).credentialRef
  assert.equal(rig.credentials.records.get(tempRef).payload.password, 'temp-pw')

  const cleared = await rig.service.saveHost({
    id: saved.host.id,
    name: 'temp-host',
    host: '127.0.0.1',
    port: mock.port,
    username: 'tester',
    auth: 'password',
    tags: ['temp'],
    clear: ['password'],
  })
  assert.equal(cleared.host.secret.fields.password, false)
  assert.equal(rig.credentials.records.has(tempRef), false)

  const deleted = await rig.service.deleteHost({ id: saved.host.id })
  assert.equal(deleted.removed, true)
})

// --- testHost / fingerprints ----------------------------------------------

test('service.testHost: draft TOFU (new -> known), saved hosts, auth failure', async () => {
  const draft = {
    name: 'draft-host',
    host: '127.0.0.1',
    port: mock.port,
    username: 'tester',
    auth: 'password',
  }
  const first = await rig.service.testHost({ draft, secret: { password: MOCK_PASSWORD } })
  assert.equal(first.ok, true)
  assert.equal(first.hostKeyStatus, 'new')
  assert.equal(first.fingerprint, mock.fingerprint)
  assert.equal(first.keyType, 'ssh-ed25519')
  assert.equal(first.banner, '')
  assert.ok(first.elapsedMs >= 0)
  assert.equal(first.error, undefined)

  const knownHosts = await rig.service.knownHostsState()
  assert.equal(knownHosts.length, 1)
  assert.equal(knownHosts[0].host, '127.0.0.1')
  assert.equal(knownHosts[0].port, mock.port)
  assert.equal(knownHosts[0].fingerprint, mock.fingerprint)

  const second = await rig.service.testHost({ draft, secret: { password: MOCK_PASSWORD } })
  assert.equal(second.ok, true)
  assert.equal(second.hostKeyStatus, 'known')

  const saved = await rig.service.testHost({ id: idOf(WEB) })
  assert.equal(saved.ok, true)
  assert.equal(saved.hostKeyStatus, 'known')
  assert.equal(saved.fingerprint, mock.fingerprint)

  const failed = await rig.service.testHost({
    draft: { ...draft, name: 'draft-bad' },
    secret: { password: 'wrong-password' },
  })
  assert.equal(failed.ok, false)
  assert.equal(failed.error.code, 'auth-failed')
  assert.equal(failed.hostKeyStatus, 'unknown')

  await assert.rejects(rig.service.testHost({ id: 'missing-host' }), { code: 'not-found' })
  await assert.rejects(rig.service.testHost({}), { code: 'invalid-host' })
})

test('service.resolveTargets: all / @tag / comma separated / name & id / errors', async () => {
  const all = await rig.service.resolveTargets('all')
  assert.equal(all.length, hostCount)

  const webGroup = await rig.service.resolveTargets('@web')
  assert.deepEqual(webGroup.map((host) => host.id), [idOf(WEB)])
  const prodGroup = await rig.service.resolveTargets('@prod')
  assert.deepEqual(prodGroup.map((host) => host.id).sort(), [idOf(DB), idOf(WEB)].sort())
  const byName = await rig.service.resolveTargets('web-1')
  assert.equal(byName[0].id, idOf(WEB))
  const byUpperName = await rig.service.resolveTargets('WEB-1')
  assert.equal(byUpperName[0].id, idOf(WEB))
  const byId = await rig.service.resolveTargets(idOf(DB))
  assert.equal(byId[0].id, idOf(DB))
  const comma = await rig.service.resolveTargets('web-1,db-1')
  assert.deepEqual(comma.map((host) => host.id).sort(), [idOf(WEB), idOf(DB)].sort())
  const spaces = await rig.service.resolveTargets('web-1 db-1')
  assert.equal(spaces.length, 2)
  const dedup = await rig.service.resolveTargets('web-1,web-1')
  assert.equal(dedup.length, 1)

  await assert.rejects(rig.service.resolveTargets('@nope'), { code: 'unknown-target' })
  await assert.rejects(rig.service.resolveTargets('nope'), { code: 'unknown-target' })
  await assert.rejects(rig.service.resolveTargets(''), { code: 'unknown-target' })
})

test('service.resolveTargets: an empty inventory reports no-hosts', async () => {
  const emptyRig = createRig()
  try {
    await assert.rejects(emptyRig.service.resolveTargets('all'), { code: 'no-hosts' })
    await assert.rejects(emptyRig.service.run({ targets: 'all', command: 'echo hi' }), { code: 'no-hosts' })
  } finally {
    await emptyRig.dispose()
  }
})

// --- run -------------------------------------------------------------------

test('service.run: single host stdout/exit code/cwd and RunResult shape', async () => {
  const result = await rig.service.run({ targets: WEB, command: 'echo service-ok' })
  assert.equal(result.command, 'echo service-ok')
  assert.equal(result.cwd, null)
  assert.equal(result.session, null)
  assert.equal(result.sudo, false)
  assert.ok(result.startedAt > 0)
  assert.ok(result.durationMs >= 0)
  assert.equal(result.hosts.length, 1)
  const entry = result.hosts[0]
  assert.equal(entry.hostId, idOf(WEB))
  assert.equal(entry.name, WEB)
  assert.equal(entry.host, '127.0.0.1')
  assert.equal(entry.port, mock.port)
  assert.equal(entry.username, 'tester')
  assert.equal(entry.status, 'ok')
  assert.equal(entry.exitCode, 0)
  assert.equal(entry.signal, null)
  assert.equal(entry.output, 'service-ok\n')
  assert.equal(entry.truncated, false)
  assert.ok(entry.durationMs >= 0)
  assert.equal(entry.error, undefined)
  assert.equal(entry.fingerprint, mock.fingerprint)
  assert.equal(entry.hostKeyStatus, 'known')

  const cwdResult = await rig.service.run({ targets: WEB, command: 'pwd', cwd: mock.homeDir })
  assert.equal(cwdResult.cwd, mock.homeDir)
  assert.equal(cwdResult.hosts[0].status, 'ok')
  assert.equal(cwdResult.hosts[0].output, `${mock.homeDir}\n`)
})

test('service.run: non-zero exit and stderr are reported without an error object', async () => {
  const result = await rig.service.run({ targets: WEB, command: 'echo err-line >&2; exit 4' })
  const entry = result.hosts[0]
  assert.equal(entry.status, 'error')
  assert.equal(entry.exitCode, 4)
  assert.match(entry.output, /\[stderr\]\nerr-line/)
  assert.equal(entry.error, undefined)
})

test('service.run: output cap is applied per host', async () => {
  const result = await rig.service.run({
    targets: WEB,
    command: "head -c 20000 /dev/zero | tr '\\0' 'a'",
    maxOutputBytes: 1024,
  })
  const entry = result.hosts[0]
  assert.equal(entry.truncated, true)
  assert.ok(Buffer.byteLength(entry.output) <= 1024)
})

test('service.run: multi-host parallel exec isolates failures', async () => {
  const result = await rig.service.run({ targets: 'all', command: 'echo multi-ok' })
  assert.equal(result.hosts.length, hostCount)
  for (const id of [WEB, DB, SUDO_WRONG, KEY_HOST]) {
    const entry = hostResult(result, id)
    assert.equal(entry.status, 'ok', `${id}: ${JSON.stringify(entry)}`)
    assert.equal(entry.output, 'multi-ok\n')
  }
  const broken = hostResult(result, BROKEN)
  assert.equal(broken.status, 'error')
  assert.equal(broken.error.code, 'connect-failed')
  assert.equal(broken.output, '')

  const prod = await rig.service.run({ targets: '@prod', command: 'echo prod-ok' })
  assert.equal(prod.hosts.length, 2)
  assert.ok(prod.hosts.every((entry) => entry.status === 'ok' && entry.output === 'prod-ok\n'))
})

test('service.run: timeout produces status timeout + error.code timeout', async () => {
  const startedAt = Date.now()
  const result = await rig.service.run({ targets: WEB, command: 'sleep 5', timeoutSec: 1 })
  const entry = result.hosts[0]
  assert.equal(entry.status, 'timeout')
  assert.equal(entry.exitCode, null)
  assert.deepEqual(entry.error, { code: 'timeout', message: '执行超时（1s）。' })
  assert.ok(Date.now() - startedAt < 5000)
})

test('service.run: abort signal produces status error + error.code aborted', async () => {
  const controller = new AbortController()
  setTimeout(() => controller.abort(), 100)
  const result = await rig.service.run({ targets: WEB, command: 'sleep 5', signal: controller.signal })
  const entry = result.hosts[0]
  assert.equal(entry.status, 'error')
  assert.equal(entry.error.code, 'aborted')
})

// --- persistent sessions ---------------------------------------------------

test('service.run: persistent session keeps cd/export and is listed/closed', async () => {
  const first = await rig.service.run({
    targets: WEB,
    command: 'mkdir -p "$HOME/persist-svc" && cd "$HOME/persist-svc" && pwd',
    session: 's1',
    agentId: 'agent-a',
  })
  const entry = first.hosts[0]
  assert.equal(entry.status, 'ok')
  assert.equal(entry.output, `${mock.homeDir}/persist-svc\n`)
  assert.equal(entry.sessionKey, `agent-a::s1::${idOf(WEB)}`)
  assert.equal(first.session, 's1')

  const sessions = rig.service.listSessions({ agentId: 'agent-a' })
  assert.equal(sessions.length, 1)
  assert.equal(sessions[0].key, `agent-a::s1::${idOf(WEB)}`)
  assert.equal(sessions[0].label, 's1')
  assert.equal(sessions[0].hostId, idOf(WEB))
  assert.equal(sessions[0].hostName, WEB)
  assert.equal(sessions[0].agentId, 'agent-a')
  assert.ok(sessions[0].createdAt > 0)
  assert.ok(sessions[0].lastUsedAt >= sessions[0].createdAt)

  const pwdAgain = await rig.service.run({ targets: WEB, command: 'pwd', session: 's1', agentId: 'agent-a' })
  assert.equal(pwdAgain.hosts[0].output, `${mock.homeDir}/persist-svc\n`)

  const exported = await rig.service.run({
    targets: WEB,
    command: 'export CB_SVC_VALUE=7',
    session: 's1',
    agentId: 'agent-a',
  })
  assert.equal(exported.hosts[0].status, 'ok')
  const readBack = await rig.service.run({
    targets: WEB,
    command: 'echo "v=$CB_SVC_VALUE"',
    session: 's1',
    agentId: 'agent-a',
  })
  assert.equal(readBack.hosts[0].output, 'v=7\n')

  // Sudo inside a persistent session goes through the heredoc as well.
  const sudoSession = await rig.service.run({
    targets: WEB,
    command: 'echo sudo-session-ok',
    session: 's1',
    sudo: true,
    agentId: 'agent-a',
  })
  assert.equal(sudoSession.hosts[0].status, 'ok', JSON.stringify(sudoSession.hosts[0]))
  assert.equal(sudoSession.hosts[0].output, 'sudo-session-ok\n')

  assert.equal(rig.service.listSessions().length, 1)
  const key = sessions[0].key
  assert.equal(await rig.service.closeSession({ key }), true)
  assert.equal(rig.service.listSessions({ agentId: 'agent-a' }).length, 0)
  assert.equal(await rig.service.closeSession({ key }), false)
  await assert.rejects(rig.service.closeSession({}), { code: 'invalid-session' })

  // closeAllSessions closes everything from this agent (and others).
  await rig.service.run({ targets: WEB, command: 'true', session: 'a1', agentId: 'agent-a' })
  await rig.service.run({ targets: WEB, command: 'true', session: 'b1', agentId: 'agent-b' })
  assert.equal(rig.service.listSessions().length, 2)
  assert.equal(await rig.service.closeAllSessions(), 2)
  assert.equal(rig.service.listSessions().length, 0)
})

// --- sudo ------------------------------------------------------------------

test('service.sudo: correct password succeeds, wrong password and missing secret fail', async () => {
  const ok = await rig.service.run({ targets: WEB, command: 'echo sudo-ok', sudo: true })
  assert.equal(ok.sudo, true)
  assert.equal(ok.hosts[0].status, 'ok', JSON.stringify(ok.hosts[0]))
  assert.equal(ok.hosts[0].output, 'sudo-ok\n')

  const wrong = await rig.service.run({ targets: SUDO_WRONG, command: 'echo should-not-run', sudo: true })
  const wrongEntry = wrong.hosts[0]
  assert.equal(wrongEntry.status, 'error')
  assert.equal(wrongEntry.exitCode, 1)
  assert.match(wrongEntry.output, /sudo: a password is required/)
  assert.ok(!wrongEntry.output.includes('should-not-run'))

  const missing = await rig.service.run({ targets: KEY_HOST, command: 'echo nope', sudo: true })
  const missingEntry = missing.hosts[0]
  assert.equal(missingEntry.status, 'error')
  assert.equal(missingEntry.error.code, 'sudo-password-missing')
})

// --- transfers -------------------------------------------------------------

test('service.upload/download: file round-trip, ~ expansion and {name} templates', async () => {
  const localDir = makeTempDir('rb-transfer-')
  const source = path.join(localDir, 'source.txt')
  const payload = 'remote-bash upload payload\n'.repeat(32)
  fs.writeFileSync(source, payload)

  const uploaded = await rig.service.upload({ targets: WEB, localPath: source, remotePath: '~/uploaded.txt' })
  assert.equal(uploaded.action, 'upload')
  assert.equal(uploaded.localPath, source)
  assert.equal(uploaded.remotePath, '~/uploaded.txt')
  assert.ok(uploaded.durationMs >= 0)
  assert.equal(uploaded.hosts.length, 1)
  assert.equal(uploaded.hosts[0].status, 'ok')
  assert.equal(uploaded.hosts[0].bytes, Buffer.byteLength(payload))
  assert.equal(fs.readFileSync(path.join(mock.homeDir, 'uploaded.txt'), 'utf8'), payload)

  const cat = await rig.service.run({ targets: WEB, command: 'cat "$HOME/uploaded.txt"' })
  assert.equal(cat.hosts[0].output, payload)

  // Multi-host upload with a {name} template.
  const templated = await rig.service.upload({
    targets: `${WEB},${DB}`,
    localPath: source,
    remotePath: '~/up-{name}.txt',
  })
  assert.equal(templated.hosts.length, 2)
  assert.ok(templated.hosts.every((entry) => entry.status === 'ok'))
  for (const name of [WEB, DB]) {
    assert.equal(fs.readFileSync(path.join(mock.homeDir, `up-${name}.txt`), 'utf8'), payload)
  }

  // Download a file back.
  fs.writeFileSync(path.join(mock.homeDir, 'remote-download.txt'), 'downloaded-content')
  const downloadDir = makeTempDir('rb-download-')
  const target = path.join(downloadDir, 'downloaded.txt')
  const downloaded = await rig.service.download({
    targets: WEB,
    remotePath: '~/remote-download.txt',
    localPath: target,
  })
  assert.equal(downloaded.action, 'download')
  assert.equal(downloaded.hosts[0].status, 'ok')
  assert.equal(downloaded.hosts[0].bytes, Buffer.byteLength('downloaded-content'))
  assert.equal(fs.readFileSync(target, 'utf8'), 'downloaded-content')

  // Multi-host download with {name}/{basename} templates.
  const templatedDownload = await rig.service.download({
    targets: `${WEB},${DB}`,
    remotePath: '~/remote-download.txt',
    localPath: path.join(downloadDir, '{name}-{basename}'),
  })
  assert.ok(templatedDownload.hosts.every((entry) => entry.status === 'ok'))
  for (const name of [WEB, DB]) {
    assert.equal(fs.readFileSync(path.join(downloadDir, `${name}-remote-download.txt`), 'utf8'), 'downloaded-content')
  }

  const missing = await rig.service.download({
    targets: WEB,
    remotePath: '~/does-not-exist.txt',
    localPath: path.join(downloadDir, 'nope.txt'),
  })
  assert.equal(missing.hosts[0].status, 'error')
  assert.equal(missing.hosts[0].error.code, 'remote-not-found')
})

test('service.download: file destinations for explicit path vs existing directory (single/multi host)', async () => {
  const sharedRemote = path.join(mock.homeDir, 'shared-file.txt')
  fs.writeFileSync(sharedRemote, 'shared-content')

  // Single host + explicit file path (does not exist yet) is used verbatim.
  const explicitDir = makeTempDir('rb-dl-explicit-')
  const explicitPath = path.join(explicitDir, 'renamed.txt')
  const explicit = await rig.service.download({
    targets: WEB,
    remotePath: '~/shared-file.txt',
    localPath: explicitPath,
  })
  assert.equal(explicit.hosts[0].status, 'ok', JSON.stringify(explicit.hosts[0]))
  assert.equal(explicit.hosts[0].localPath, explicitPath)
  assert.equal(fs.readFileSync(explicitPath, 'utf8'), 'shared-content')

  // Single host + existing directory -> <dir>/<basename>.
  const singleDir = makeTempDir('rb-dl-single-dir-')
  const single = await rig.service.download({
    targets: WEB,
    remotePath: '~/shared-file.txt',
    localPath: singleDir,
  })
  assert.equal(single.hosts[0].status, 'ok', JSON.stringify(single.hosts[0]))
  assert.equal(single.hosts[0].localPath, path.join(singleDir, 'shared-file.txt'))
  assert.equal(fs.readFileSync(path.join(singleDir, 'shared-file.txt'), 'utf8'), 'shared-content')

  // Multiple hosts + existing directory -> <dir>/<name>-<basename>.
  const multiDir = makeTempDir('rb-dl-multi-dir-')
  const multi = await rig.service.download({
    targets: `${WEB},${DB}`,
    remotePath: '~/shared-file.txt',
    localPath: multiDir,
  })
  assert.equal(multi.hosts.length, 2)
  for (const entry of multi.hosts) assert.equal(entry.status, 'ok', JSON.stringify(entry))
  for (const name of [WEB, DB]) {
    const file = path.join(multiDir, `${name}-shared-file.txt`)
    assert.equal(fs.readFileSync(file, 'utf8'), 'shared-content')
  }
})

test('service.download: directory destinations for single and multiple hosts', async () => {
  const remoteTree = path.join(mock.homeDir, 'shared-tree')
  fs.mkdirSync(path.join(remoteTree, 'nested'), { recursive: true })
  fs.writeFileSync(path.join(remoteTree, 'x.txt'), 'X')
  fs.writeFileSync(path.join(remoteTree, 'nested', 'y.txt'), 'Y')

  // Single host + localPath directory -> recursive copy under localPath.
  const singleTarget = makeTempDir('rb-dl-tree-single-')
  const single = await rig.service.download({
    targets: WEB,
    remotePath: '~/shared-tree',
    localPath: singleTarget,
  })
  assert.equal(single.hosts[0].status, 'ok', JSON.stringify(single.hosts[0]))
  assert.equal(fs.readFileSync(path.join(singleTarget, 'x.txt'), 'utf8'), 'X')
  assert.equal(fs.readFileSync(path.join(singleTarget, 'nested', 'y.txt'), 'utf8'), 'Y')

  // Multiple hosts + localPath directory -> <dir>/<name>/... per host.
  const multiTarget = makeTempDir('rb-dl-tree-multi-')
  const multi = await rig.service.download({
    targets: `${WEB},${DB}`,
    remotePath: '~/shared-tree',
    localPath: multiTarget,
  })
  assert.equal(multi.hosts.length, 2)
  for (const entry of multi.hosts) assert.equal(entry.status, 'ok', JSON.stringify(entry))
  for (const name of [WEB, DB]) {
    assert.equal(fs.readFileSync(path.join(multiTarget, name, 'x.txt'), 'utf8'), 'X')
    assert.equal(fs.readFileSync(path.join(multiTarget, name, 'nested', 'y.txt'), 'utf8'), 'Y')
  }
})

test('service.upload/download: directories are transferred recursively', async () => {
  const localDir = makeTempDir('rb-dir-')
  const tree = path.join(localDir, 'tree')
  fs.mkdirSync(path.join(tree, 'nested'), { recursive: true })
  fs.writeFileSync(path.join(tree, 'a.txt'), 'A')
  fs.writeFileSync(path.join(tree, 'nested', 'b.txt'), 'B')

  const uploaded = await rig.service.upload({ targets: WEB, localPath: tree, remotePath: '~/remote-tree' })
  assert.equal(uploaded.hosts[0].status, 'ok', JSON.stringify(uploaded.hosts[0]))
  assert.equal(fs.readFileSync(path.join(mock.homeDir, 'remote-tree', 'a.txt'), 'utf8'), 'A')
  assert.equal(fs.readFileSync(path.join(mock.homeDir, 'remote-tree', 'nested', 'b.txt'), 'utf8'), 'B')

  const downloadDir = makeTempDir('rb-dir-down-')
  const destination = path.join(downloadDir, 'downloaded-tree')
  const downloaded = await rig.service.download({
    targets: WEB,
    remotePath: '~/remote-tree',
    localPath: destination,
  })
  assert.equal(downloaded.hosts[0].status, 'ok', JSON.stringify(downloaded.hosts[0]))
  assert.equal(fs.readFileSync(path.join(destination, 'a.txt'), 'utf8'), 'A')
  assert.equal(fs.readFileSync(path.join(destination, 'nested', 'b.txt'), 'utf8'), 'B')

  // One unreachable host must not fail the transfer for the healthy one.
  const mixed = await rig.service.upload({
    targets: `${WEB},${BROKEN}`,
    localPath: tree,
    remotePath: '~/remote-tree-2',
  })
  assert.equal(mixed.hosts.length, 2)
  const webEntry = mixed.hosts.find((entry) => entry.hostId === idOf(WEB))
  const brokenEntry = mixed.hosts.find((entry) => entry.hostId === idOf(BROKEN))
  assert.equal(webEntry.status, 'ok')
  assert.equal(brokenEntry.status, 'error')
  assert.equal(brokenEntry.error.code, 'connect-failed')
})

// --- known hosts / approve -------------------------------------------------

test('service known hosts: forget, changed fingerprint detection and approve', async () => {
  const stateBefore = await rig.service.knownHostsState()
  assert.equal(stateBefore.length, 1)
  assert.equal(stateBefore[0].fingerprint, mock.fingerprint)

  const forgotten = await rig.service.forgetKnownHost({ host: '127.0.0.1', port: mock.port })
  assert.equal(forgotten.removed, true)
  assert.deepEqual(forgotten.state.knownHosts, [])
  const forgottenAgain = await rig.service.forgetKnownHost({ host: '127.0.0.1', port: mock.port })
  assert.equal(forgottenAgain.removed, false)

  // Next contact records the fingerprint again (TOFU).
  const reTofu = await rig.service.testHost({ id: idOf(WEB) })
  assert.equal(reTofu.ok, true)
  assert.equal(reTofu.hostKeyStatus, 'new')

  // Simulate a changed server key by planting a different fingerprint.
  await rig.knownHosts.approve({
    host: '127.0.0.1',
    port: mock.port,
    keyType: 'ssh-ed25519',
    fingerprint: BOGUS_FINGERPRINT,
  })
  const changed = await rig.service.testHost({ id: idOf(WEB) })
  assert.equal(changed.ok, false)
  assert.equal(changed.hostKeyStatus, 'changed')
  assert.equal(changed.fingerprint, mock.fingerprint)
  assert.equal(changed.error.code, 'host-key-changed')
  assert.equal(changed.error.details.previousFingerprint, BOGUS_FINGERPRINT)

  await assert.rejects(
    rig.service.approveFingerprint({ host: '127.0.0.1', port: mock.port, fingerprint: 'SHA256:wrong' }),
    { code: 'fingerprint-mismatch' },
  )
  const approved = await rig.service.approveFingerprint({ host: '127.0.0.1', port: mock.port, fingerprint: mock.fingerprint })
  assert.equal(approved.entry.fingerprint, mock.fingerprint)
  assert.ok(approved.state.knownHosts.some((entry) => entry.fingerprint === mock.fingerprint))

  const afterApprove = await rig.service.testHost({ id: idOf(WEB) })
  assert.equal(afterApprove.ok, true)
  assert.equal(afterApprove.hostKeyStatus, 'known')
  await assert.rejects(
    rig.service.approveFingerprint({ host: '127.0.0.1', port: mock.port }),
    { code: 'no-pending-fingerprint' },
  )
  await assert.rejects(rig.service.approveFingerprint({}), { code: 'invalid-host' })

  // A changed key also shows up in run() results.
  const runResult = await rig.service.run({ targets: WEB, command: 'echo hi' })
  assert.equal(runResult.hosts[0].status, 'ok')
})

// --- delete + credentials cleanup -----------------------------------------

test('service.deleteHost: removes host, credentials and its persistent sessions', async () => {
  const toDelete = await rig.service.saveHost({
    name: 'delete-me',
    host: '127.0.0.1',
    port: mock.port,
    username: 'tester',
    auth: 'password',
    tags: [],
    secret: { password: MOCK_PASSWORD },
  })
  const deleteRef = (await rig.inventory.get(toDelete.host.id)).credentialRef
  assert.ok(rig.credentials.records.has(deleteRef))

  const result = await rig.service.deleteHost({ id: toDelete.host.id })
  assert.equal(result.removed, true)
  assert.ok(!result.state.hosts.some((host) => host.id === toDelete.host.id))
  assert.equal(rig.credentials.records.has(deleteRef), false)
  await assert.rejects(rig.service.deleteHost({ id: toDelete.host.id }), { code: 'not-found' })
  await assert.rejects(rig.service.deleteHost({}), { code: 'invalid-host' })

  // Deleting a host closes the persistent sessions it owns.
  const sessionHost = await rig.service.saveHost({
    name: 'sess-tmp',
    host: '127.0.0.1',
    port: mock.port,
    username: 'tester',
    auth: 'password',
    tags: [],
    secret: { password: MOCK_PASSWORD },
  })
  const sessionRun = await rig.service.run({
    targets: 'sess-tmp',
    command: 'echo session-tmp',
    session: 'tmp',
    agentId: 'agent-del',
  })
  assert.equal(sessionRun.hosts[0].status, 'ok')
  assert.equal(rig.service.listSessions({ agentId: 'agent-del' }).length, 1)
  await rig.service.deleteHost({ id: sessionHost.host.id })
  assert.equal(rig.service.listSessions({ agentId: 'agent-del' }).length, 0)
})

// --- credentials service missing ------------------------------------------

test('service without a credentials service fails closed for secrets', async () => {
  const noCredentialsRig = createRig({ credentials: null })
  try {
    const empty = await noCredentialsRig.service.state()
    assert.equal(empty.credentialsAvailable, false)

    await assert.rejects(
      noCredentialsRig.service.saveHost({
        name: 'no-cred',
        host: '127.0.0.1',
        port: mock.port,
        username: 'tester',
        auth: 'password',
        secret: { password: MOCK_PASSWORD },
      }),
      { code: 'credentials-unavailable' },
    )

    const saved = await noCredentialsRig.service.saveHost({
      name: 'no-cred',
      host: '127.0.0.1',
      port: mock.port,
      username: 'tester',
      auth: 'password',
    })
    assert.equal(saved.host.secret.available, false)
    assert.equal(saved.host.secret.configured, false)

    const runResult = await noCredentialsRig.service.run({ targets: 'no-cred', command: 'echo hi' })
    assert.equal(runResult.hosts[0].status, 'error')
    assert.equal(runResult.hosts[0].error.code, 'missing-secret')
  } finally {
    await noCredentialsRig.dispose()
  }
})
