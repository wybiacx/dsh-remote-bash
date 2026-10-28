/**
 * Contract tests for the browser RPC channel (host/rpc.js, INTERFACE §3):
 * route registration, client-request/server-response envelope, method
 * dispatch, success/error values and request validation.
 */

import assert from 'node:assert/strict'
import { after, before, test } from 'node:test'

import { installRpc, RPC_ENDPOINT } from '../host/rpc.js'
import {
  cleanupTempDirs,
  createRig,
  MOCK_PASSWORD,
  quietLogger,
  saveMockHost,
  startMockServer,
} from './helpers.mjs'

let mock
let rig
let harness
let route
let webId

const RPC_PATH = `/api/${RPC_ENDPOINT}`

function installRpcHarness(service) {
  const routes = []
  const ctx = {
    get(name) {
      if (name !== 'connection') return undefined
      return {
        fetch: {
          register(registered) {
            routes.push(registered)
            return async () => {
              const index = routes.indexOf(registered)
              if (index >= 0) routes.splice(index, 1)
            }
          },
        },
      }
    },
    effect(factory) {
      return factory()
    },
  }
  const dispose = installRpc(ctx, { service, logger: quietLogger })
  return { routes, dispose }
}

function tick() {
  return new Promise((resolve) => setImmediate(resolve))
}

function rpcRequest(method, payload, overrides = {}) {
  const body = {
    type: 'client-request',
    rpcId: 'rpc-1',
    method: RPC_ENDPOINT,
    payload: { method, payload: payload ?? {} },
    ...overrides,
  }
  return new Request(`http://127.0.0.1${RPC_PATH}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}

async function rpcCall(method, payload, overrides) {
  const response = await route.fetch(rpcRequest(method, payload, overrides))
  let body
  try {
    body = await response.json()
  } catch {
    body = await response.text()
  }
  return { response, body }
}

async function rpcValue(method, payload) {
  const { response, body } = await rpcCall(method, payload)
  assert.equal(response.status, 200)
  assert.equal(body.type, 'server-response')
  assert.equal(body.rpcId, 'rpc-1')
  assert.equal(body.result.ok, true, JSON.stringify(body.result))
  return body.result.value
}

async function rpcError(method, payload) {
  const { response, body } = await rpcCall(method, payload)
  assert.equal(response.status, 200)
  assert.equal(body.type, 'server-response')
  assert.equal(body.result.ok, false)
  return body.result.error
}

before(async () => {
  mock = await startMockServer()
  rig = createRig()
  webId = (await saveMockHost(rig, mock, { name: 'web-1', tags: ['web'] })).host.id
  harness = installRpcHarness(rig.service)
  await tick()
  route = harness.routes[0]
  assert.ok(route, 'RPC route was not registered')
})

after(async () => {
  await harness?.dispose?.()
  await mock?.close()
  await rig?.dispose()
  cleanupTempDirs()
})

test('rpc: registers the documented route shape', () => {
  assert.equal(RPC_ENDPOINT, 'remote-bash/rpc')
  assert.equal(route.path, RPC_PATH)
  assert.deepEqual(route.methods, ['POST'])
  assert.equal(route.requestBody, 'buffered')
  assert.equal(typeof route.fetch, 'function')
})

test('rpc: state returns the State shape', async () => {
  const state = await rpcValue('state', {})
  assert.equal(state.settings.dataDir, rig.root)
  assert.equal(state.credentialsAvailable, true)
  assert.equal(state.hosts.length, 1)
  assert.equal(state.hosts[0].id, webId)
  assert.equal(state.hosts[0].secret.fields.password, true)
  assert.deepEqual(state.groups, [{ tag: 'web', hostIds: [webId] }])
  assert.ok(Array.isArray(state.knownHosts))
  assert.ok(Array.isArray(state.sessions))
})

test('rpc: host.save / host.test / host.delete round-trip', async () => {
  const saved = await rpcValue('host.save', {
    name: 'rpc-host',
    host: '127.0.0.1',
    port: mock.port,
    username: 'tester',
    auth: 'password',
    tags: ['rpc'],
    secret: { password: MOCK_PASSWORD },
  })
  assert.ok(saved.host.id)
  assert.equal(saved.host.secret.fields.password, true)
  assert.ok(saved.state.hosts.some((host) => host.id === saved.host.id))

  const tested = await rpcValue('host.test', { id: saved.host.id })
  assert.equal(tested.ok, true)
  assert.equal(tested.fingerprint, mock.fingerprint)
  assert.equal(tested.hostKeyStatus, 'new')

  const forgotten = await rpcValue('knownHost.forget', { host: '127.0.0.1', port: mock.port })
  assert.equal(forgotten.state.knownHosts.length, 0)

  const deleted = await rpcValue('host.delete', { id: saved.host.id })
  assert.equal(deleted.removed, true)
  assert.ok(!deleted.state.hosts.some((host) => host.id === saved.host.id))
})

test('rpc: knownHost.approve works after a detected fingerprint change', async () => {
  const tested = await rpcValue('host.test', { id: webId })
  assert.equal(tested.ok, true)

  await rig.knownHosts.approve({
    host: '127.0.0.1',
    port: mock.port,
    keyType: 'ssh-ed25519',
    fingerprint: `SHA256:${'C'.repeat(43)}`,
  })
  const changed = await rpcValue('host.test', { id: webId })
  assert.equal(changed.ok, false)
  assert.equal(changed.hostKeyStatus, 'changed')

  const approved = await rpcValue('knownHost.approve', { host: '127.0.0.1', port: mock.port, fingerprint: changed.fingerprint })
  assert.equal(approved.entry.fingerprint, mock.fingerprint)
  assert.equal(approved.state.knownHosts[0].fingerprint, mock.fingerprint)

  const afterApprove = await rpcValue('host.test', { id: webId })
  assert.equal(afterApprove.ok, true)
  assert.equal(afterApprove.hostKeyStatus, 'known')
})

test('rpc: session.close / session.closeAll manage persistent sessions', async () => {
  await rig.service.run({ targets: 'web-1', command: 'true', session: 'rpc-session', agentId: 'agent-rpc' })
  const sessions = await rpcValue('state', {})
  assert.equal(sessions.sessions.length, 1)
  const key = sessions.sessions[0].key

  const closed = await rpcValue('session.close', { key })
  // INTERFACE §3 says `{ state }`; the Host additionally returns the boolean
  // result as `closed` (harmless superset used by the settings page).
  assert.equal(closed.closed, true)
  assert.equal(closed.state.sessions.length, 0)
  assert.equal((await rpcValue('state', {})).sessions.length, 0)

  await rig.service.run({ targets: 'web-1', command: 'true', session: 'one', agentId: 'agent-rpc' })
  await rig.service.run({ targets: 'web-1', command: 'true', session: 'two', agentId: 'agent-rpc' })
  const closeAll = await rpcValue('session.closeAll', {})
  assert.equal(closeAll.closed, 2)
  assert.equal(closeAll.state.sessions.length, 0)
})

test('rpc: domain errors become {ok:false,error:{code,message,details}}', async () => {
  const error = await rpcError('host.delete', {})
  assert.equal(error.code, 'invalid-host')
  assert.equal(typeof error.message, 'string')
  assert.deepEqual(error.details, {})

  const unknown = await rpcError('does.not.exist', {})
  assert.equal(unknown.code, 'unknown-method')

  const notFound = await rpcError('host.test', { id: 'missing-host' })
  assert.equal(notFound.code, 'not-found')
})

test('rpc: rejects malformed requests and wrong HTTP methods', async () => {
  const badMethod = await route.fetch(new Request(`http://127.0.0.1${RPC_PATH}`, { method: 'GET' }))
  assert.equal(badMethod.status, 405)

  const badContentType = await route.fetch(
    new Request(`http://127.0.0.1${RPC_PATH}`, { method: 'POST', body: 'x' }),
  )
  assert.equal(badContentType.status, 415)

  const badBody = await route.fetch(
    new Request(`http://127.0.0.1${RPC_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{nope',
    }),
  )
  assert.equal(badBody.status, 400)

  const wrongEnvelope = await rpcCall('state', {}, { type: 'something-else' })
  assert.equal(wrongEnvelope.body.result.ok, false)
  assert.equal(wrongEnvelope.body.result.error.code, 'bad-request')

  const missingPayload = await route.fetch(
    new Request(`http://127.0.0.1${RPC_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ type: 'client-request', rpcId: 'r2', method: RPC_ENDPOINT, payload: {} }),
    }),
  )
  const missingPayloadBody = await missingPayload.json()
  assert.equal(missingPayloadBody.result.ok, false)
  assert.equal(missingPayloadBody.result.error.code, 'bad-request')
})

test('rpc: synchronous registration awaits asynchronous cleanup exactly once', async () => {
  let releases = 0
  let finish
  const pending = new Promise(resolve => { finish = resolve })
  const dispose = installRpc({
    get: () => ({ fetch: { register: () => async () => { releases++; await pending } } }),
    effect: factory => factory(),
  }, { service: {}, logger: quietLogger })
  const cleanup = dispose()
  assert.equal(dispose(), cleanup)
  let complete = false
  cleanup.then(() => { complete = true })
  await tick()
  assert.equal(releases, 1)
  assert.equal(complete, false)
  finish()
  await cleanup
  assert.equal(complete, true)
})

test('rpc: legacy registration resolving after unload is cleaned up', async () => {
  let resolveRegistration, releases = 0
  const pending = new Promise(resolve => { resolveRegistration = resolve })
  const dispose = installRpc({
    get: () => ({ fetch: { register: () => pending } }), effect: factory => factory(),
  }, { service: {}, logger: quietLogger })
  const cleanup = dispose()
  resolveRegistration(async () => { releases++ })
  await cleanup
  await dispose()
  assert.equal(releases, 1)
})

test('rpc: rejected registration and asynchronous cleanup failures are observed', async () => {
  const errors = [], warnings = []
  const logger = { error: (...args) => errors.push(args), warn: (...args) => warnings.push(args) }
  for (const register of [
    () => Promise.reject(new Error('registration failed')),
    () => async () => { throw new Error('cleanup failed') },
  ]) {
    const dispose = installRpc({ get: () => ({ fetch: { register } }), effect: factory => factory() }, { service: {}, logger })
    await dispose()
  }
  assert.equal(errors.length, 1)
  assert.equal(warnings.length, 1)
})

test('rpc: cleanup has its own route and preserves warnings and public pending state', async () => {
  const requests = []
  const value = { warnings: [{ code: 'cleanup-pending', message: 'Retry cleanup' }], state: { hosts: [], pendingCleanup: [{ id: 'retired-id', name: 'old-host' }] } }
  const isolated = installRpcHarness({ cleanupHost: async payload => { requests.push(payload); return value } })
  try {
    const response = await isolated.routes[0].fetch(rpcRequest('host.cleanup', { id: 'retired-id' }))
    assert.deepEqual((await response.json()).result, { ok: true, value })
    assert.deepEqual(requests, [{ id: 'retired-id' }])
  } finally { await isolated.dispose() }
})

test('rpc: installs without a connection service without throwing', () => {
  const dispose = installRpc(
    { get: () => undefined, effect: (factory) => factory(), warn() {} },
    { service: rig.service, logger: quietLogger },
  )
  assert.equal(typeof dispose, 'function')
})
