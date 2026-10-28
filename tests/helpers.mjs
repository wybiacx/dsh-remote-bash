/**
 * Shared helpers for the Remote Bash end-to-end tests.
 *
 * - temp dirs under os.tmpdir() with an explicit cleanup registry
 * - fake DSH credentials store (the record half of `ctx.credentials`)
 * - fake DSH approval service
 * - a "rig" that wires host/** the same way host/plugin.js does
 * - a real mock SSH server plus fixture hosts / keys
 */

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

import { createPaths } from '../host/paths.js'
import { createInventory } from '../host/inventory.js'
import { createKnownHosts } from '../host/knownhosts.js'
import { createSecretStore } from '../host/credentials.js'
import { createApprovalGate } from '../host/approval.js'
import { createService } from '../host/service.js'
import { createSshClient } from '../host/ssh.js'
import { createMockServer, MOCK_PASSWORD, MOCK_SUDO_PASSWORD, MOCK_USERNAME } from './mock-ssh-server.mjs'

export const FIXTURES = path.join(import.meta.dirname, 'fixtures')
export const KEY_NO_PASS = fs.readFileSync(path.join(FIXTURES, 'id_ed25519'), 'utf8')
export const KEY_NO_PASS_PUB = fs.readFileSync(path.join(FIXTURES, 'id_ed25519.pub'), 'utf8')
export const KEY_WITH_PASS = fs.readFileSync(path.join(FIXTURES, 'id_ed25519_pass'), 'utf8')
export const KEY_WITH_PASS_PUB = fs.readFileSync(path.join(FIXTURES, 'id_ed25519_pass.pub'), 'utf8')
export const KEY_PASSPHRASE = 'key-secret'

export { MOCK_PASSWORD, MOCK_SUDO_PASSWORD, MOCK_USERNAME }

const tempDirs = new Set()

export const quietLogger = {
  info() {},
  warn() {},
  error() {},
  debug() {},
}

export function makeTempDir(prefix = 'rb-test-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix))
  tempDirs.add(dir)
  return dir
}

export function removeTempDir(dir) {
  if (!dir) return
  tempDirs.delete(dir)
  fs.rmSync(dir, { recursive: true, force: true })
}

/** Remove every temp dir registered by makeTempDir(). Safe to call repeatedly. */
export function cleanupTempDirs() {
  for (const dir of [...tempDirs]) {
    try {
      fs.rmSync(dir, { recursive: true, force: true })
    } catch {
      /* best effort */
    }
    tempDirs.delete(dir)
  }
}

/** Fake `ctx.credentials` record space, modelled on dsh-credentials. */
export function createFakeCredentials({ available = true } = {}) {
  if (!available) {
    const unavailable = new Error('credentials service unavailable')
    unavailable.code = 'credentials-unavailable'
    return {
      records: new Map(),
      calls: [],
      async readRecord() {
        throw unavailable
      },
      async modifyRecord() {
        throw unavailable
      },
      async deleteRecord() {
        throw unavailable
      },
    }
  }
  const records = new Map()
  const calls = []
  return {
    records,
    calls,
    async readRecord(key) {
      calls.push({ op: 'readRecord', key })
      return records.get(key)
    },
    async describeRecord(key) {
      const record = records.get(key)
      if (!record) return { configured: false, writable: true }
      return { configured: true, kind: record.kind, writable: true }
    },
    async listRecords() {
      return [...records].map(([key, record]) => ({ key, kind: record.kind }))
    },
    async modifyRecord(key, mutate) {
      calls.push({ op: 'modifyRecord', key })
      const current = records.get(key)
      const next = await mutate(current)
      if (next === undefined) return current
      records.set(key, next)
      return next
    },
    async deleteRecord(key) {
      calls.push({ op: 'deleteRecord', key })
      records.delete(key)
    },
  }
}

/** Fake `ctx.approval`: records every request and returns the configured outcome. */
export function createFakeApproval(outcome = 'allowed-once') {
  return {
    calls: [],
    outcome,
    async request(request) {
      this.calls.push(request)
      return typeof this.outcome === 'function' ? this.outcome(request) : this.outcome
    },
  }
}

/** Start a mock SSH server that accepts both fixture public keys. */
export async function startMockServer(options = {}) {
  const dataDir = options.dataDir ?? makeTempDir('rb-mock-')
  const mock = createMockServer({
    dataDir,
    authorizedKeys: options.authorizedKeys ?? [KEY_NO_PASS_PUB, KEY_WITH_PASS_PUB],
    ...options,
  })
  await mock.listen()
  return mock
}

/** A normalized inventory host pointing at the mock server. */
export function hostInput(mock, overrides = {}) {
  return {
    name: 'web-1',
    host: '127.0.0.1',
    port: mock.port,
    username: MOCK_USERNAME,
    auth: 'password',
    keyPath: '',
    tags: [],
    note: '',
    sudo: false,
    ...overrides,
  }
}

/**
 * Wire host/** modules exactly like host/plugin.js does (minus DSH runtime
 * services), with fake credentials + approval.
 */
export function createRig({ dataDir, config = {}, credentials } = {}) {
  const root = dataDir ?? makeTempDir('rb-rig-')
  const paths = createPaths(root)
  const inventory = createInventory({ filePath: paths.inventoryFile })
  const knownHosts = createKnownHosts({ filePath: paths.knownHostsFile })
  // `credentials: null` wires the rig without a credentials service, which is
  // how host/plugin.js behaves when ctx.get('credentials') is undefined.
  const fakeCredentials = credentials === null ? null : credentials ?? createFakeCredentials()
  const secrets = createSecretStore({ credentials: fakeCredentials ?? undefined })
  const approval = createFakeApproval()
  const settings = {
    dataDir: paths.root,
    defaultTimeoutSec: 60,
    maxParallelHosts: 8,
    maxOutputBytes: 32768,
    sessionIdleMinutes: 30,
    approvalMode: 'dangerous',
    extraDangerousPatterns: [],
    ...config,
  }
  const service = createService({
    config: settings,
    paths,
    inventory,
    knownHosts,
    secrets,
    approval,
    logger: quietLogger,
  })
  const gate = createApprovalGate({ approval, mode: settings.approvalMode, logger: quietLogger })
  const ssh = createSshClient({ knownHosts, logger: quietLogger })

  return {
    root,
    paths,
    inventory,
    knownHosts,
    credentials: fakeCredentials,
    secrets,
    approval,
    gate,
    service,
    ssh,
    settings,
    async saveHost(overrides = {}, secret = {}) {
      return service.saveHost({ ...hostInput({ port: 1 }, overrides), secret })
    },
    async dispose() {
      service.dispose()
      removeTempDir(root)
    },
  }
}

/** Save the default mock-backed host with password + sudo password. */
export async function saveMockHost(rig, mock, overrides = {}, secret = {}) {
  const input = hostInput(mock, overrides)
  return rig.service.saveHost({
    ...input,
    secret: {
      password: MOCK_PASSWORD,
      sudoPassword: MOCK_SUDO_PASSWORD,
      ...secret,
    },
  })
}

/** Poll `fn` until it returns truthy (used for time-based assertions). */
export async function waitUntil(fn, { timeoutMs = 3000, intervalMs = 20 } = {}) {
  const deadline = Date.now() + timeoutMs
  let lastError = null
  while (Date.now() < deadline) {
    try {
      const value = await fn()
      if (value) return value
    } catch (error) {
      lastError = error
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }
  if (lastError) throw lastError
  throw new Error('waitUntil timed out')
}
