import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { after, test } from 'node:test'
import { EventEmitter } from 'node:events'
import ssh2 from 'ssh2'
import { createService } from '../host/service.js'
import { installTools } from '../host/tools.js'
import { cleanupTempDirs, createRig, createFakeCredentials, makeTempDir, saveMockHost, startMockServer } from './helpers.mjs'

after(cleanupTempDirs)
const input = (name = 'web') => ({ name, host: 'old.example', username: 'user', auth: 'password', tags: ['web'] })
function rigFor(t, options) {
  const rig = createRig(options)
  t.after(() => rig.dispose())
  return rig
}
function toolsFor(rig) {
  const tools = new Map()
  installTools({ tools: { register(tool) { tools.set(tool.name, tool); return () => tools.delete(tool.name) } }, effect: (fn) => fn() },
    { service: rig.service, config: rig.settings, gate: rig.gate })
  return tools
}

test('save: credential write failure preserves old endpoint and allows retry', async (t) => {
  const rig = rigFor(t)
  const saved = await rig.service.saveHost({ ...input(), secret: { password: 'old-password' } })
  const before = await rig.inventory.get(saved.host.id)
  const modify = rig.credentials.modifyRecord
  rig.credentials.modifyRecord = async () => { throw new Error('injected write failure') }
  await assert.rejects(rig.service.saveHost({ ...input(), id: saved.host.id, host: 'new.example', secret: { password: 'new-password' } }), { code: 'credentials-error' })
  assert.deepEqual(await rig.inventory.get(saved.host.id), before)
  assert.equal((await rig.secrets.readRef(before.credentialRef)).password, 'old-password')
  await assert.rejects(rig.service.saveHost({ ...input('second'), secret: { password: 'pw' } }))
  assert.equal((await rig.service.state()).hosts.length, 1)
  rig.credentials.modifyRecord = modify
  const retried = await rig.service.saveHost({ ...input('second'), secret: { password: 'pw' } })
  assert.equal(retried.host.name, 'second')
})

test('save: inventory commit failure preserves the previous credential reference', async (t) => {
  const rig = rigFor(t)
  const saved = await rig.service.saveHost({ ...input(), secret: { password: 'old-password' } })
  const before = await rig.inventory.get(saved.host.id)
  const commit = rig.inventory.commitHost
  rig.inventory.commitHost = async () => { throw new Error('injected commit failure') }
  await assert.rejects(rig.service.saveHost({ id: saved.host.id, secret: { password: 'new-password' } }), /commit failure/)
  rig.inventory.commitHost = commit
  assert.deepEqual(await rig.inventory.get(saved.host.id), before)
  assert.equal((await rig.secrets.readRef(before.credentialRef)).password, 'old-password')
  assert.equal(rig.credentials.records.size, 1)
})

test('delete: cleanup failure is visible and a same-name replacement never inherits secrets', async (t) => {
  const rig = rigFor(t)
  const saved = await rig.service.saveHost({ ...input(), secret: { password: 'old-password' } })
  const oldRef = (await rig.inventory.get(saved.host.id)).credentialRef
  const remove = rig.credentials.deleteRecord
  rig.credentials.deleteRecord = async () => { throw new Error('injected deletion failure') }
  const deleted = await rig.service.deleteHost({ id: saved.host.id })
  assert.equal(deleted.removed, true)
  assert.equal(deleted.warnings[0].code, 'credential-cleanup-pending')
  assert.deepEqual(deleted.state.pendingCleanup, [{ id: saved.host.id, name: saved.host.name }])
  const replacement = await rig.service.saveHost({ ...input(), host: 'different.example' })
  assert.notEqual(replacement.host.id, saved.host.id)
  assert.equal(replacement.host.secret.configured, false)
  assert.equal((await rig.inventory.get(replacement.host.id)).credentialRef, null)
  assert.equal(rig.credentials.records.has(oldRef), true)
  rig.credentials.deleteRecord = remove
  const cleaned = await rig.service.cleanupHost({ id: saved.host.id })
  assert.deepEqual(cleaned.warnings, [])
  assert.equal(rig.credentials.records.has(oldRef), false)
  assert.equal(cleaned.state.hosts[0].id, replacement.host.id)
})

test('save: concurrent credential patches preserve both fields and cleanup does not delete host', async (t) => {
  const rig = rigFor(t)
  const saved = await rig.service.saveHost({ ...input(), secret: { password: 'old-password' } })
  await Promise.all([
    rig.service.saveHost({ id: saved.host.id, secret: { password: 'new-password' } }),
    rig.service.saveHost({ id: saved.host.id, secret: { sudoPassword: 'new-sudo-password' } }),
  ])
  const host = await rig.inventory.get(saved.host.id)
  assert.deepEqual(await rig.secrets.readRef(host.credentialRef), { password: 'new-password', sudoPassword: 'new-sudo-password' })
  const cleaned = await rig.service.cleanupHost({ id: saved.host.id })
  assert.equal(cleaned.state.hosts[0].id, saved.host.id)
  assert.equal(cleaned.state.hosts[0].secret.fields.password, true)
})

test('recovery: only journaled inactive credentials are removed on restart', async (t) => {
  const rig = rigFor(t)
  const saved = await rig.service.saveHost({ ...input(), secret: { password: 'active-password' } })
  const abandoned = rig.secrets.createRef()
  await rig.inventory.queueCleanup([{ ref: abandoned, id: saved.host.id, name: saved.host.name }])
  await rig.secrets.stage(null, { password: 'abandoned-password' }, { ref: abandoned })
  await rig.secrets.write('unknown-legacy-orphan', { password: 'keep-password' })
  await rig.service.dispose()
  rig.service = createService({ config: rig.settings, paths: rig.paths, inventory: rig.inventory, knownHosts: rig.knownHosts, secrets: rig.secrets })
  const state = await rig.service.state()
  assert.deepEqual(state.pendingCleanup, [])
  assert.equal(rig.credentials.records.has(abandoned), false)
  assert.equal(state.hosts[0].secret.fields.password, true)
  assert.equal((await rig.secrets.read('unknown-legacy-orphan')).password, 'keep-password')
  t.after(() => rig.service.dispose())
})

test('execution plan: newly added group members are not included after approval', async (t) => {
  const rig = rigFor(t, { config: { approvalMode: 'always' } })
  const first = await rig.service.saveHost(input())
  rig.approval.outcome = async () => {
    await rig.service.saveHost(input('production'))
    return 'allowed-once'
  }
  // No passwords: execution must stop before making a network connection.
  const result = await toolsFor(rig).get('remote_bash').execute({ targets: '@web', command: 'echo harmless' }, { agent: { id: 'review' } })
  assert.equal(result.hosts.length, 1)
  assert.equal(result.hosts[0].hostId, first.host.id)
  assert.equal(result.hosts[0].error.code, 'missing-secret')
})

test('execution plan: changed host is rejected and a plan cannot be executed twice', async (t) => {
  const rig = rigFor(t)
  const saved = await rig.service.saveHost(input())
  const plan = await rig.service.prepareRun({ targets: 'web', command: 'echo harmless' })
  await rig.service.saveHost({ id: saved.host.id, host: 'new.example', sudo: true })
  const result = await rig.service.run({ plan })
  assert.equal(result.hosts[0].error.code, 'target-changed')
  await assert.rejects(rig.service.run({ plan }), { code: 'invalid-plan' })
})

test('execution plan: explicit sudo false does not ask for host-default elevation', async (t) => {
  const rig = rigFor(t)
  await rig.service.saveHost({ ...input(), sudo: true })
  const result = await toolsFor(rig).get('remote_bash').execute({ targets: 'web', command: 'echo harmless', sudo: false }, { agent: { id: 'review' } })
  assert.equal(rig.approval.calls.length, 0)
  assert.equal(result.sudo, false)
})

test('known hosts: concurrent first contacts accept only one conflicting fingerprint', async (t) => {
  const rig = rigFor(t)
  const entries = ['SHA256:first', 'SHA256:second'].map((fingerprint) => ({ host: 'test.example', port: 22, keyType: 'ssh-ed25519', fingerprint }))
  const results = await Promise.allSettled(entries.map((entry) => rig.knownHosts.verify(entry)))
  assert.equal(results.filter((item) => item.status === 'fulfilled').length, 1)
  assert.equal(results.find((item) => item.status === 'rejected').reason.code, 'host-key-changed')
  assert.equal((await rig.knownHosts.verify(entries[0])).status, 'known')
})

test('host test: draft overrides and clear apply without saving credentials', async (t) => {
  const mock = await startMockServer()
  const rig = rigFor(t)
  t.after(() => mock.close())
  const saved = await saveMockHost(rig, mock)
  const original = await rig.inventory.get(saved.host.id)
  const result = await rig.service.testHost({ id: saved.host.id, draft: { ...saved.host, username: 'wrong-user' } })
  assert.equal(result.ok, false)
  assert.equal(result.error.code, 'auth-failed')
  assert.deepEqual(result.target, { host: '127.0.0.1', port: mock.port })
  const cleared = await rig.service.testHost({ id: saved.host.id, clear: ['password'] })
  assert.equal(cleared.error.code, 'missing-secret')
  assert.deepEqual(await rig.inventory.get(saved.host.id), original)
  assert.equal((await rig.service.state()).hosts[0].secret.fields.password, true)
})

test('multi-host download: host names cannot escape the destination directory', async (t) => {
  const mock = await startMockServer()
  const rig = rigFor(t)
  t.after(() => mock.close())
  await saveMockHost(rig, mock, { name: '../outside' })
  await saveMockHost(rig, mock, { name: 'safe' })
  fs.writeFileSync(path.join(mock.homeDir, 'download.txt'), 'payload')
  const destination = makeTempDir('rb-download-name-')
  const result = await rig.service.download({ targets: 'all', remotePath: '~/download.txt', localPath: destination })
  assert.equal(result.hosts.length, 2)
  for (const host of result.hosts) {
    assert.equal(host.status, 'ok', JSON.stringify(host))
    assert.equal(path.dirname(host.localPath), destination)
    assert.equal(fs.readFileSync(host.localPath, 'utf8'), 'payload')
  }
})

test('dispose: aborts active one-shot commands, waits for cleanup and rejects later mutations', async (t) => {
  let started
  const began = new Promise((resolve) => { started = resolve })
  let ended = 0
  class Client extends EventEmitter {
    connect() { queueMicrotask(() => this.emit('ready')) }
    exec(command, callback) {
      const channel = new EventEmitter()
      channel.stderr = new EventEmitter()
      channel.end = () => {}
      channel.close = () => channel.emit('close')
      callback(null, channel)
      started()
    }
    end() { ended++ }
    destroy() { ended++ }
  }
  const originalClient = ssh2.Client
  ssh2.Client = Client
  t.after(() => { ssh2.Client = originalClient })
  const rig = rigFor(t)
  const saved = await rig.service.saveHost({ ...input(), secret: { password: 'dummy-password' } })
  const running = rig.service.run({ targets: saved.host.id, command: 'sleep 10' })
  await Promise.race([began, running.then((result) => { throw new Error(`command ended before mock started: ${JSON.stringify(result)}`) })])
  await rig.service.dispose()
  assert.equal((await running).hosts[0].error.code, 'aborted')
  assert.ok(ended > 0)
  await assert.rejects(rig.service.saveHost(input('after-dispose')), { code: 'aborted' })
  assert.equal((await rig.inventory.list()).length, 1)
})

test('dispose: waits for an already-started credential commit', async (t) => {
  const rig = rigFor(t)
  let writing
  const began = new Promise((resolve) => { writing = resolve })
  let release
  const blocked = new Promise((resolve) => { release = resolve })
  const modify = rig.credentials.modifyRecord
  rig.credentials.modifyRecord = async (...args) => { writing(); await blocked; return modify(...args) }
  const saving = rig.service.saveHost({ ...input(), secret: { password: 'dummy-password' } })
  await began
  let finished = false
  const disposal = rig.service.dispose().then(() => { finished = true })
  await Promise.resolve()
  assert.equal(finished, false)
  release()
  await saving
  await disposal
  const host = (await rig.inventory.list())[0]
  assert.equal((await rig.secrets.readRef(host.credentialRef)).password, 'dummy-password')
  assert.deepEqual(await rig.inventory.listPendingCleanup(), [])
})

test('v1 compatibility: existing id and credential survive first save upgrade', async (t) => {
  const credentials = createFakeCredentials()
  const rig = rigFor(t, { credentials })
  await rig.service.state()
  await rig.service.dispose()
  const legacy = { version: 1, hosts: [{ ...input(), id: 'legacy-web', createdAt: 1, updatedAt: 1 }] }
  fs.writeFileSync(rig.paths.inventoryFile, JSON.stringify(legacy))
  await rig.secrets.write('legacy-web', { password: 'legacy-password' })
  const upgraded = createRig({ dataDir: rig.root, credentials })
  t.after(() => upgraded.dispose())
  const state = await upgraded.service.state()
  assert.equal(state.hosts[0].id, 'legacy-web')
  assert.equal(state.hosts[0].secret.fields.password, true)
  await upgraded.service.saveHost({ id: 'legacy-web', note: 'upgraded' })
  const disk = JSON.parse(fs.readFileSync(rig.paths.inventoryFile, 'utf8'))
  assert.equal(disk.version, 2)
  assert.equal(fs.existsSync(`${rig.paths.inventoryFile}.v1.bak`), true)
  assert.equal(fs.readFileSync(rig.paths.inventoryFile, 'utf8').includes('legacy-password'), false)
  assert.equal(path.basename(rig.paths.inventoryFile), 'inventory.json')
})
