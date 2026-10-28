/**
 * Contract/unit tests for the pure host/** modules (no SSH):
 * paths, inventory, known_hosts, credentials adapter, danger patterns,
 * approval gate, util helpers and config normalization.
 */

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { after, test } from 'node:test'

import ssh2 from 'ssh2'

import { createPaths, expandHome, resolveDataDir } from '../host/paths.js'
import { createInventory, normalizeHostInput } from '../host/inventory.js'
import { createKnownHosts, fingerprintOf, keyTypeOf } from '../host/knownhosts.js'
import { createSecretStore, recordKey } from '../host/credentials.js'
import { assessCommand, DEFAULT_PATTERNS } from '../host/danger.js'
import { createApprovalGate, requireApproval } from '../host/approval.js'
import { normalizeConfig } from '../host/plugin.js'
import { clampInt, quoteShell, truncateBytes, uniqueStrings } from '../host/util.js'
import {
  cleanupTempDirs,
  createFakeApproval,
  createFakeCredentials,
  FIXTURES,
  KEY_NO_PASS_PUB,
  makeTempDir,
  quietLogger,
} from './helpers.mjs'

const { utils } = ssh2

after(() => cleanupTempDirs())

function inventoryHost(overrides = {}) {
  return {
    name: 'web-1',
    host: '10.0.0.5',
    port: 22,
    username: 'deploy',
    auth: 'password',
    tags: ['web'],
    ...overrides,
  }
}

// --- paths -----------------------------------------------------------------

test('paths: expandHome handles ~, ~/x, relative and empty inputs', () => {
  assert.equal(expandHome('~'), os.homedir())
  assert.equal(expandHome('~/sub/dir'), path.join(os.homedir(), 'sub/dir'))
  assert.equal(expandHome('/abs/path'), path.resolve('/abs/path'))
  assert.equal(expandHome('relative/dir'), path.resolve('relative/dir'))
  assert.equal(expandHome(''), '')
  assert.equal(expandHome(null), '')
})

test('paths: createPaths resolves dataDir and fixed file names', () => {
  const root = makeTempDir('rb-paths-')
  const paths = createPaths(root)
  assert.equal(paths.root, path.resolve(root))
  assert.equal(paths.inventoryFile, path.join(path.resolve(root), 'inventory.json'))
  assert.equal(paths.knownHostsFile, path.join(path.resolve(root), 'known_hosts.json'))
})

test('paths: resolveDataDir falls back to DSH_HOME/remote-bash', () => {
  const previous = process.env.DSH_HOME
  const fakeHome = makeTempDir('rb-dsh-home-')
  process.env.DSH_HOME = fakeHome
  try {
    assert.equal(resolveDataDir(''), path.join(path.resolve(fakeHome), 'remote-bash'))
    assert.equal(resolveDataDir(undefined), path.join(path.resolve(fakeHome), 'remote-bash'))
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
  }
  const custom = makeTempDir('rb-custom-')
  assert.equal(resolveDataDir(custom), path.resolve(custom))
})

// --- inventory -------------------------------------------------------------

test('inventory: missing file loads as an empty v1 document', async () => {
  const dir = makeTempDir('rb-inv-')
  const inventory = createInventory({ filePath: path.join(dir, 'inventory.json') })
  assert.deepEqual(await inventory.load(), { version: 1, hosts: [] })
  assert.deepEqual(await inventory.list(), [])
  assert.equal(await inventory.get('nope'), undefined)
})

test('inventory: upsert derives a slug id, normalizes defaults and persists', async () => {
  const dir = makeTempDir('rb-inv-')
  const filePath = path.join(dir, 'inventory.json')
  const inventory = createInventory({ filePath })
  const created = await inventory.upsert(inventoryHost({ name: 'Web One', port: undefined, tags: 'web, prod' }))
  assert.equal(created.id, 'web-one')
  assert.equal(created.name, 'Web One')
  assert.equal(created.port, 22)
  assert.equal(created.auth, 'password')
  assert.deepEqual(created.tags, ['web', 'prod'])
  assert.ok(created.createdAt > 0)
  assert.equal(created.updatedAt, created.createdAt)
  assert.equal(created.password, undefined, 'inventory must never store secrets')

  // A second instance over the same file sees the persisted host.
  const reloaded = createInventory({ filePath })
  const list = await reloaded.list()
  assert.equal(list.length, 1)
  assert.equal(list[0].id, 'web-one')
  assert.equal((fs.statSync(filePath).mode & 0o777), 0o600)

  const updated = await reloaded.upsert({ id: 'web-one', name: 'Web One', username: 'root', auth: 'key' })
  assert.equal(updated.username, 'root')
  assert.equal(updated.auth, 'key')
  assert.equal(updated.createdAt, created.createdAt)
  assert.ok(updated.updatedAt >= created.updatedAt)
  assert.equal(await reloaded.get('web-one').then((host) => host.username), 'root')
})

test('inventory: validation errors carry the documented codes', async () => {
  const dir = makeTempDir('rb-inv-')
  const inventory = createInventory({ filePath: path.join(dir, 'inventory.json') })

  await assert.rejects(inventory.upsert({ host: 'h', username: 'u', auth: 'password' }), (error) => {
    assert.equal(error.code, 'invalid-host')
    assert.match(error.message, /名称/)
    return true
  })
  await assert.rejects(inventory.upsert(inventoryHost({ host: 'bad host' })), { code: 'invalid-host' })
  await assert.rejects(inventory.upsert(inventoryHost({ port: 0 })), { code: 'invalid-host' })
  await assert.rejects(inventory.upsert(inventoryHost({ port: 70000 })), { code: 'invalid-host' })
  await assert.rejects(inventory.upsert(inventoryHost({ port: 'abc' })), { code: 'invalid-host' })
  await assert.rejects(inventory.upsert(inventoryHost({ username: '' })), { code: 'invalid-host' })
  await assert.rejects(inventory.upsert(inventoryHost({ auth: 'telnet' })), { code: 'invalid-host' })
  await assert.rejects(
    inventory.upsert({ id: 'does-not-exist', ...inventoryHost() }),
    { code: 'not-found' },
  )

  await inventory.upsert(inventoryHost({ name: 'primary' }))
  await assert.rejects(inventory.upsert(inventoryHost({ name: 'PRIMARY' })), { code: 'duplicate-name' })
  // Same name is fine when it is the same record.
  await inventory.upsert({ id: 'primary', ...inventoryHost({ name: 'PRIMARY' }) })
})

test('inventory: remove reports whether a host existed', async () => {
  const dir = makeTempDir('rb-inv-')
  const inventory = createInventory({ filePath: path.join(dir, 'inventory.json') })
  const host = await inventory.upsert(inventoryHost())
  assert.equal(await inventory.remove('missing'), false)
  assert.equal(await inventory.remove(host.id), true)
  assert.deepEqual(await inventory.list(), [])
})

test('inventory: normalizeHostInput is a pure function with slug collision handling', () => {
  const first = normalizeHostInput(inventoryHost({ name: 'Web' }), { existing: null, others: [] })
  assert.equal(first.id, 'web')
  // Same slug, different display name: the id gets the -2 suffix.
  const second = normalizeHostInput(inventoryHost({ name: 'Web!' }), { existing: null, others: [first] })
  assert.equal(second.id, 'web-2')
  const existing = { ...first, username: 'old' }
  const preserved = normalizeHostInput({ username: 'new' }, { existing, others: [] })
  assert.equal(preserved.id, 'web')
  assert.equal(preserved.name, 'Web')
  assert.equal(preserved.username, 'new')
  assert.equal(preserved.host, existing.host)
})

// --- known_hosts -----------------------------------------------------------

function generatedHostKey() {
  const pair = utils.generateKeyPairSync('ed25519')
  const parsed = utils.parseKey(pair.public)
  return { pair, blob: parsed.getPublicSSH() }
}

test('knownhosts: fingerprintOf matches ssh-keygen SHA256 format', () => {
  const { pair, blob } = generatedHostKey()
  const expected = `SHA256:${crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`
  assert.equal(fingerprintOf(blob), expected)
  assert.match(fingerprintOf(blob), /^SHA256:[A-Za-z0-9+/]{43}$/)
  assert.equal(keyTypeOf(blob), 'ssh-ed25519')

  // Cross-check against the OpenSSH client itself.
  const pubFile = path.join(makeTempDir('rb-kh-'), 'host.pub')
  fs.writeFileSync(pubFile, `${pair.public.trim()}\n`)
  const output = execFileSync('ssh-keygen', ['-lf', pubFile], { encoding: 'utf8' })
  assert.ok(output.includes(expected), `ssh-keygen said: ${output}`)
  assert.equal(keyTypeOf(Buffer.from('not-a-key')), 'unknown')
  assert.equal(keyTypeOf(KEY_NO_PASS_PUB), 'ssh-ed25519')
})

test('knownhosts: TOFU record/find/approve/forget lifecycle', async () => {
  const dir = makeTempDir('rb-kh-')
  const filePath = path.join(dir, 'known_hosts.json')
  const knownHosts = createKnownHosts({ filePath })
  const first = generatedHostKey()
  const second = generatedHostKey()

  assert.equal(await knownHosts.find('10.0.0.5', 22), undefined)
  const recorded = await knownHosts.record({
    host: '10.0.0.5',
    port: 22,
    keyType: 'ssh-ed25519',
    fingerprint: fingerprintOf(first.blob),
  })
  assert.equal(recorded.host, '10.0.0.5')
  assert.equal(recorded.port, 22)
  assert.ok(recorded.firstSeenAt > 0)
  assert.equal(recorded.lastSeenAt, recorded.firstSeenAt)

  const found = await knownHosts.find('10.0.0.5', 22)
  assert.equal(found.fingerprint, fingerprintOf(first.blob))

  // record() must refresh lastSeenAt without overwriting a different fingerprint.
  await new Promise((resolve) => setTimeout(resolve, 5))
  const refreshed = await knownHosts.record({
    host: '10.0.0.5',
    port: 22,
    keyType: 'ssh-ed25519',
    fingerprint: fingerprintOf(second.blob),
  })
  assert.equal(refreshed.fingerprint, fingerprintOf(first.blob))
  assert.ok(refreshed.lastSeenAt > found.lastSeenAt)

  // approve() is the user-confirmed path and does overwrite.
  const approved = await knownHosts.approve({
    host: '10.0.0.5',
    port: 22,
    keyType: 'ssh-ed25519',
    fingerprint: fingerprintOf(second.blob),
  })
  assert.equal(approved.fingerprint, fingerprintOf(second.blob))
  assert.equal(approved.firstSeenAt, recorded.firstSeenAt)

  // Persistence + lookup is host/port sensitive.
  const reloaded = createKnownHosts({ filePath })
  assert.equal((await reloaded.find('10.0.0.5', 22)).fingerprint, fingerprintOf(second.blob))
  assert.equal(await reloaded.find('10.0.0.5', 2222), undefined)
  assert.equal(await reloaded.find('other-host', 22), undefined)
  assert.equal((await reloaded.list()).length, 1)

  assert.equal(await reloaded.forget('10.0.0.5', 22), true)
  assert.equal(await reloaded.forget('10.0.0.5', 22), false)
  assert.deepEqual(await reloaded.list(), [])
})

// --- credentials -----------------------------------------------------------

test('credentials: recordKey and unavailable-service behaviour', async () => {
  assert.equal(recordKey('web-1'), 'remote-bash/web-1')

  const missing = createSecretStore({ credentials: undefined })
  assert.equal(missing.available(), false)
  assert.deepEqual(await missing.read('web-1'), {})
  assert.deepEqual(await missing.flags('web-1'), {
    available: false,
    configured: false,
    fields: { password: false, passphrase: false, privateKey: false, sudoPassword: false },
  })
  await assert.rejects(missing.write('web-1', { password: 'x' }), { code: 'credentials-unavailable' })
  await assert.rejects(missing.write('web-1', {}, { clear: ['password'] }), { code: 'credentials-unavailable' })
})

test('credentials: write/read/flags/clear round-trip through the fake store', async () => {
  const fake = createFakeCredentials()
  const store = createSecretStore({ credentials: fake })
  assert.equal(store.available(), true)

  await store.write('web-1', { password: 'pw-1', sudoPassword: 'sudo-1' })
  assert.deepEqual(await store.read('web-1'), { password: 'pw-1', sudoPassword: 'sudo-1' })
  assert.deepEqual(await store.flags('web-1'), {
    available: true,
    configured: true,
    fields: { password: true, passphrase: false, privateKey: false, sudoPassword: true },
  })
  const record = fake.records.get('remote-bash/web-1')
  assert.equal(record.kind, 'grant')
  assert.deepEqual(record.payload, { password: 'pw-1', sudoPassword: 'sudo-1' })

  // Patch only touches the given fields.
  await store.write('web-1', { passphrase: 'pp' })
  assert.deepEqual(await store.read('web-1'), { password: 'pw-1', sudoPassword: 'sudo-1', passphrase: 'pp' })

  // clear removes listed fields; unknown clear entries are ignored.
  await store.write('web-1', {}, { clear: ['passphrase', 'not-a-field'] })
  assert.deepEqual(await store.read('web-1'), { password: 'pw-1', sudoPassword: 'sudo-1' })

  // Clearing everything deletes the record.
  await store.write('web-1', {}, { clear: ['password', 'sudoPassword'] })
  assert.equal(fake.records.has('remote-bash/web-1'), false)
  assert.deepEqual(await store.read('web-1'), {})

  // clear() always deletes.
  await store.write('web-2', { password: 'pw-2' })
  await store.clear('web-2')
  assert.equal(fake.records.has('remote-bash/web-2'), false)

  // Ignore non-grant records.
  fake.records.set('remote-bash/web-3', { kind: 'api-key', env: {} })
  assert.deepEqual(await store.read('web-3'), {})
})

// --- danger ----------------------------------------------------------------

test('danger: destructive commands are flagged', () => {
  const cases = [
    ['rm -rf /', 'rm-dangerous'],
    ['rm -rf ~', 'rm-dangerous'],
    ['rm -rf *', 'rm-dangerous'],
    ['rm -rf ..', 'rm-dangerous'],
    ['rm -rf ~/.cache', 'rm-system-path'],
    ['rm -rf ~/.ssh', 'rm-system-path'],
    ['rm -rf $HOME/.config', 'rm-system-path'],
    ['rm -rf /etc', 'rm-system-path'],
    ['rm -rf /opt/data', 'rm-system-path'],
    ['mkfs.ext4 /dev/sda1', 'mkfs'],
    ['dd if=/dev/zero of=/dev/sda bs=1M', 'dd-device'],
    ['shutdown -h now', 'shutdown'],
    ['reboot', 'shutdown'],
    ['systemctl stop sshd', 'systemctl-critical'],
    ['iptables -F', 'firewall-flush'],
    ['userdel bob', 'user-admin'],
    ['crontab -r', 'crontab-remove'],
    ['chmod -R 777 /etc', 'recursive-perm'],
    ['fdisk /dev/sda', 'disk-partition'],
    ['echo x > /etc/hosts', 'etc-overwrite'],
    ['docker system prune -af', 'docker-destructive'],
    ['truncate -s 0 /var/log/syslog', 'truncate-zero'],
    ['sudo systemctl restart nginx', 'sudo'],
  ]
  for (const [command, id] of cases) {
    const result = assessCommand(command)
    assert.equal(result.dangerous, true, `expected dangerous: ${command}`)
    assert.ok(result.matches.some((match) => match.id === id), `${command} -> ${JSON.stringify(result.matches)}`)
    for (const match of result.matches) {
      assert.equal(typeof match.label, 'string')
      assert.ok(match.label.length > 0)
    }
  }
  assert.ok(DEFAULT_PATTERNS.length >= 15)
})

test('danger: ordinary commands are not flagged; extra patterns are supported', () => {
  for (const command of [
    'ls -la',
    'pwd',
    'echo hello',
    'git status',
    'cat /etc/hosts',
    'rm -rf ./build',
    'rm -rf build',
    'rm -rf /tmp/build',
    'rm -rf ~/project/dist',
    // Regression: a redirect to /dev/null followed later by /var/lib/... must not
    // be mistaken for overwriting a system config path.
    "echo 'x'; du -x -h -d1 / 2>/dev/null | sort -hr | head -12; du -sh /var/log /var/lib/docker /home/* 2>/dev/null",
  ]) {
    assert.equal(assessCommand(command).dangerous, false, `expected safe: ${command}`)
  }
  const custom = assessCommand('deploy --wipe prod', { extraPatterns: ['--wipe\\b'] })
  assert.equal(custom.dangerous, true)
  assert.equal(custom.matches[0].id, 'extra-0')
  // Invalid extra patterns are ignored rather than crashing.
  assert.equal(assessCommand('echo hi', { extraPatterns: ['[['] }).dangerous, false)
})

// --- approval gate ---------------------------------------------------------

const approvalMatches = [{ id: 'rm-dangerous', label: '递归删除危险路径' }]

function approvalRequest(overrides = {}) {
  return {
    agent: approvalAgent,
    toolName: 'remote_bash',
    callId: 'call-1',
    signal: undefined,
    command: 'rm -rf /',
    hostNames: ['web-1', 'db-1'],
    matches: approvalMatches,
    ...overrides,
  }
}

const approvalAgent = { id: 'agent-1' }

test('approval: trusted mode never asks; dangerous mode asks only for matches', async () => {
  const trustedApproval = createFakeApproval('rejected')
  const trusted = createApprovalGate({ approval: trustedApproval, mode: 'trusted', logger: quietLogger })
  assert.deepEqual(await trusted.check(approvalRequest()), { allowed: true, outcome: 'not-needed' })
  assert.equal(trustedApproval.calls.length, 0)

  const dangerousApproval = createFakeApproval('allowed-once')
  const dangerous = createApprovalGate({ approval: dangerousApproval, mode: 'dangerous', logger: quietLogger })
  assert.deepEqual(await dangerous.check(approvalRequest({ matches: [] })), { allowed: true, outcome: 'not-needed' })
  assert.equal(dangerousApproval.calls.length, 0)

  const allowed = await dangerous.check(approvalRequest())
  assert.deepEqual(allowed, { allowed: true, outcome: 'allowed-once' })
  assert.equal(dangerousApproval.calls.length, 1)
  const request = dangerousApproval.calls[0]
  assert.equal(request.agent, approvalAgent)
  assert.equal(request.toolName, 'remote_bash')
  assert.equal(request.callId, 'call-1')
  assert.match(request.reason, /rm/)
  assert.match(request.reason, /web-1/)
  assert.ok(request.displayReason.en.includes('Run'))
  assert.ok(request.displayReason.zh.includes('是否允许'))
  assert.ok(!request.displayReason.zh.includes('rm -rf'), 'displayReason must not embed the raw command')
})

test('approval: description drives the human-readable copy, audit reason keeps the command', async () => {
  const fakeApproval = createFakeApproval('allowed-once')
  const gate = createApprovalGate({ approval: fakeApproval, mode: 'dangerous', logger: quietLogger })
  const verdict = await gate.check(approvalRequest({
    command: 'dd if=/dev/zero of=/dev/null bs=1 count=1',
    description: '写入测试数据（无副作用）',
    matches: [{ id: 'dd-device', label: '直接写块设备' }],
  }))
  assert.deepEqual(verdict, { allowed: true, outcome: 'allowed-once' })
  const request = fakeApproval.calls[0]
  assert.match(request.displayReason.zh, /写入测试数据（无副作用）/)
  assert.match(request.displayReason.zh, /直接写块设备/)
  assert.ok(!request.displayReason.zh.includes('dd if=/dev/zero'), 'display copy stays concise')
  assert.match(request.reason, /写入测试数据（无副作用）/)
  assert.match(request.reason, /dd if=\/dev\/zero/, 'audit reason keeps the command')
})

test('approval: always mode asks for every command', async () => {
  const fakeApproval = createFakeApproval('allowed-once')
  const gate = createApprovalGate({ approval: fakeApproval, mode: 'always', logger: quietLogger })
  const verdict = await gate.check(approvalRequest({ matches: [] }))
  assert.deepEqual(verdict, { allowed: true, outcome: 'allowed-once' })
  assert.equal(fakeApproval.calls.length, 1)
})

test('approval: rejection/cancellation/unavailable are all fail-closed', async () => {
  for (const outcome of ['rejected', 'cancelled', 'unavailable']) {
    const gate = createApprovalGate({ approval: createFakeApproval(outcome), mode: 'dangerous', logger: quietLogger })
    const verdict = await gate.check(approvalRequest())
    assert.equal(verdict.allowed, false)
    assert.equal(verdict.outcome, outcome)
    assert.ok(verdict.reason.length > 0)
  }

  const missingService = createApprovalGate({ approval: undefined, mode: 'dangerous', logger: quietLogger })
  assert.deepEqual(await missingService.check(approvalRequest()), {
    allowed: false,
    outcome: 'unavailable',
    reason: 'DSH 审批服务不可用，已拒绝需要审批的远程命令。',
  })

  const noAgent = createApprovalGate({ approval: createFakeApproval(), mode: 'dangerous', logger: quietLogger })
  const verdict = await noAgent.check(approvalRequest({ agent: undefined }))
  assert.equal(verdict.allowed, false)
  assert.equal(verdict.outcome, 'unavailable')

  const throwing = createApprovalGate({
    approval: {
      async request() {
        throw new Error('approval broke')
      },
    },
    mode: 'dangerous',
    logger: quietLogger,
  })
  const failed = await throwing.check(approvalRequest())
  assert.equal(failed.allowed, false)
  assert.equal(failed.outcome, 'unavailable')

  const gate = createApprovalGate({ approval: createFakeApproval('rejected'), mode: 'dangerous', logger: quietLogger })
  await assert.rejects(requireApproval(gate, approvalRequest()), { code: 'approval-denied' })
  const okGate = createApprovalGate({ approval: createFakeApproval('allowed-once'), mode: 'dangerous', logger: quietLogger })
  assert.equal((await requireApproval(okGate, approvalRequest())).outcome, 'allowed-once')
})

// --- util / config ---------------------------------------------------------

test('util: quoteShell, truncateBytes, uniqueStrings, clampInt behave', () => {
  assert.equal(quoteShell("it's"), `'it'\\''s'`)
  const short = truncateBytes(Buffer.from('hello'), 10)
  assert.deepEqual(short, { buffer: Buffer.from('hello'), truncated: false })
  const long = truncateBytes(Buffer.from('a'.repeat(5000)), 1024)
  assert.equal(long.truncated, true)
  assert.ok(long.buffer.length <= 1024)
  assert.ok(long.buffer.toString().includes('输出过长'))
  assert.deepEqual(uniqueStrings(['a', ' A ', 'b', '', 3]), ['a', 'b'])
  assert.equal(clampInt('5', 1, 10, 3), 5)
  assert.equal(clampInt('nope', 1, 10, 3), 3)
  assert.equal(clampInt(99, 1, 10, 3), 10)
})

test('plugin: normalizeConfig clamps and validates settings', () => {
  assert.deepEqual(normalizeConfig({}), {
    dataDir: '',
    defaultTimeoutSec: 60,
    maxParallelHosts: 8,
    maxOutputBytes: 32768,
    sessionIdleMinutes: 30,
    approvalMode: 'dangerous',
    extraDangerousPatterns: [],
  })
  const config = normalizeConfig({
    dataDir: '  /tmp/rb  ',
    defaultTimeoutSec: 1,
    maxParallelHosts: 100,
    maxOutputBytes: 100,
    sessionIdleMinutes: 9999,
    approvalMode: 'trusted',
    extraDangerousPatterns: ['foo', 42, 'bar'],
  })
  assert.equal(config.dataDir, '/tmp/rb')
  assert.equal(config.defaultTimeoutSec, 5)
  assert.equal(config.maxParallelHosts, 32)
  assert.equal(config.maxOutputBytes, 1024)
  assert.equal(config.sessionIdleMinutes, 1440)
  assert.equal(config.approvalMode, 'trusted')
  assert.deepEqual(config.extraDangerousPatterns, ['foo', 'bar'])
  assert.equal(normalizeConfig({ approvalMode: 'yolo' }).approvalMode, 'dangerous')
})

test('fixtures: both private key kinds parse', () => {
  const plain = utils.parseKey(KEY_NO_PASS_PUB)
  assert.equal(plain.type, 'ssh-ed25519')
  const encrypted = utils.parseKey(fs.readFileSync(path.join(FIXTURES, 'id_ed25519_pass'), 'utf8'), 'key-secret')
  assert.ok(!(encrypted instanceof Error))
  assert.equal(encrypted.type, 'ssh-ed25519')
  assert.ok(!(plain instanceof Error))
})
