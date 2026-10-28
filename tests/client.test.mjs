import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import vm from 'node:vm'
import { test } from 'node:test'

// Execute the shipped module unchanged. Only React's rendering/scheduling and
// the transport are replaced: handlers, state transitions and payloads are real.
const source = await readFile(new URL('../client.js', import.meta.url), 'utf8')
const plain = value => JSON.parse(JSON.stringify(value))
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no }); return { promise, resolve, reject } }
const same = (a, b) => a && b && a.length === b.length && a.every((item, i) => Object.is(item, b[i]))

function clientHarness(rpc) {
  let current, plugin, Section, dictionaries
  const React = {
    Fragment: Symbol('fragment'),
    createElement(type, props, ...children) { return { type, props: { ...props, children } } },
    useState(initial) {
      const owner = current, i = owner.cursor++
      if (!(i in owner.hooks)) owner.hooks[i] = typeof initial === 'function' ? initial() : initial
      return [owner.hooks[i], value => {
        const next = typeof value === 'function' ? value(owner.hooks[i]) : value
        if (!Object.is(owner.hooks[i], next)) { owner.hooks[i] = next; owner.dirty = true }
      }]
    },
    useReducer(reduce, initial) { const [state, set] = React.useState(initial); return [state, action => set(previous => reduce(previous, action))] },
    useRef(initial) { return React.useState(() => ({ current: initial }))[0] },
    useId() { return React.useState('test-form')[0] },
    useCallback(fn, deps) {
      const owner = current, i = owner.cursor++
      if (!owner.hooks[i] || !same(owner.hooks[i].deps, deps)) owner.hooks[i] = { fn, deps }
      return owner.hooks[i].fn
    },
    useEffect(fn, deps) {
      const owner = current, i = owner.cursor++
      if (!owner.hooks[i] || !same(owner.hooks[i].deps, deps)) {
        const previous = owner.hooks[i]
        owner.hooks[i] = { deps, cleanup: previous?.cleanup }
        owner.effects.push(() => { previous?.cleanup?.(); owner.hooks[i].cleanup = fn() })
      }
    },
  }
  const window = {
    setTimeout: () => 1, clearTimeout() {},
    __ModuleLoader__: { load({ factory }) { plugin = factory(name => { assert.equal(name, 'react'); return React }) } },
  }
  vm.runInNewContext(source, { window, console }, { filename: 'client.js' })
  plugin.apply({
    effect: factory => factory(),
    locale: {
      register: (_ns, values) => { dictionaries = values; return () => {} },
      bind: () => key => dictionaries.en[key] ?? key,
      subscribe: () => () => {},
    },
    connection: { rpc: { async call(channel, endpoint, { method, payload }) {
      assert.equal(channel, '/api'); assert.equal(endpoint, 'remote-bash/rpc')
      return { ok: true, value: await rpc(method, plain(payload)) }
    } } },
    slots: {
      inject(name, install) { assert.equal(name, 'settings.section'); return install() },
      register(options, component) { assert.equal(options.id, 'remote-bash'); Section = component; return () => {} },
    },
  })
  function mount(component, props = {}) {
    const owner = { hooks: [], cursor: 0, effects: [], dirty: true, tree: null }
    return {
      render() {
        let rounds = 0
        do {
          owner.dirty = false; owner.cursor = 0; current = owner
          owner.tree = component(props)
          for (const effect of owner.effects.splice(0)) effect()
          assert.ok(++rounds < 30, 'render did not settle')
        } while (owner.dirty)
        return owner.tree
      },
      async flush() { await new Promise(resolve => setImmediate(resolve)); return this.render() },
      unmount() { for (const hook of owner.hooks) hook?.cleanup?.() },
    }
  }
  return { mount, section: () => mount(Section), t: key => dictionaries.en[key] ?? key }
}

function nodes(tree) {
  if (!tree || typeof tree !== 'object') return []
  if (Array.isArray(tree)) return tree.flatMap(nodes)
  return [tree, ...nodes(tree.props?.children), ...nodes(tree.props?.footer)]
}
const find = (tree, name) => nodes(tree).find(node => node.type?.name === name)
const text = tree => typeof tree === 'string' ? tree : !tree || typeof tree !== 'object' ? '' : Array.isArray(tree) ? tree.map(text).join(' ') : text(tree.props?.children)
const button = (tree, label) => nodes(tree).find(node => node.type?.name === 'Btn' && text(node) === label)
const host = { id: 'host-id', name: 'web', host: 'old.example', port: 22, username: 'user', auth: 'password', tags: [], secret: { fields: { password: true, sudoPassword: true } } }
const state = (address = 'old.example', extra = {}) => ({ hosts: [{ ...host, host: address }], groups: [], knownHosts: [], sessions: [], settings: {}, credentialsAvailable: true, pendingCleanup: [], ...extra })
async function ready(rpc) {
  const h = clientHarness(rpc), page = h.section()
  page.render(); await page.flush()
  return { h, page }
}
function editForm(h, page) {
  find(page.render(), 'HostsTab').props.onEdit(host)
  const element = find(page.render(), 'HostFormModal')
  const form = h.mount(element.type, element.props)
  form.render()
  return form
}
const input = (form, suffix) => nodes(form.render()).find(node => node.props?.id === `test-form-${suffix}`)

test('client: editing tests current draft, secrets and clear; trust uses returned target', async () => {
  const calls = []
  const { h, page } = await ready(async (method, payload) => {
    calls.push({ method, payload })
    if (method === 'host.test') return { ok: false, hostKeyStatus: 'changed', fingerprint: 'SHA256:new', target: { host: 'tested.example', port: 2200 } }
    if (method === 'knownHost.approve') return { state: state() }
    return state()
  })
  const form = editForm(h, page)
  input(form, 'host').props.onChange('edited.example')
  input(form, 'port').props.onChange('2222')
  input(form, 'password').props.onChange('synthetic-new-password')
  input(form, 'sudopassword').props.onClear()
  await button(form.render(), 'Test connection').props.onClick()
  const tested = calls.find(call => call.method === 'host.test').payload
  assert.equal(tested.id, host.id)
  assert.equal(tested.draft.host, 'edited.example')
  assert.equal(tested.draft.port, 2222)
  assert.deepEqual(tested.secret, { password: 'synthetic-new-password' })
  assert.deepEqual(tested.clear, ['sudoPassword'])
  const panel = find(form.render(), 'TestResultPanel')
  await panel.props.onTrust('SHA256:new')
  assert.deepEqual(calls.find(call => call.method === 'knownHost.approve').payload, { host: 'tested.example', port: 2200, fingerprint: 'SHA256:new' })
})

test('client: changed form invalidates visible and late test results, even after reverting', async () => {
  const pending = deferred()
  const { h, page } = await ready(method => method === 'host.test' ? pending.promise : state())
  const form = editForm(h, page)
  const running = button(form.render(), 'Test connection').props.onClick()
  input(form, 'host').props.onChange('other.example'); form.render()
  input(form, 'host').props.onChange('old.example'); form.render()
  pending.resolve({ ok: false, hostKeyStatus: 'changed', target: { host: 'old.example', port: 22 }, fingerprint: 'SHA256:old' })
  await running
  const panel = find(form.render(), 'TestResultPanel')
  assert.equal(panel.props.result, null)
  assert.equal(panel.props.onTrust, null)
})

test('client: settled test disappears on credential edits and stale trust handler is inert', async () => {
  let approvals = 0
  const { h, page } = await ready(method => {
    if (method === 'host.test') return { ok: false, hostKeyStatus: 'changed', target: { host: 'old.example', port: 22 }, fingerprint: 'SHA256:old' }
    if (method === 'knownHost.approve') approvals++
    return state()
  })
  const form = editForm(h, page)
  await button(form.render(), 'Test connection').props.onClick()
  const staleTrust = find(form.render(), 'TestResultPanel').props.onTrust
  input(form, 'password').props.onChange('changed'); form.render()
  assert.equal(find(form.render(), 'TestResultPanel').props.result, null)
  await staleTrust('SHA256:old')
  assert.equal(approvals, 0)
})

test('client: stale refresh cannot replace saved state or warning notice', async () => {
  const oldRefresh = deferred(); let reads = 0
  const { page } = await ready(method => {
    if (method === 'state') return ++reads === 1 ? state() : oldRefresh.promise
    if (method === 'host.save') return { state: state('new.example'), warnings: [{ code: 'cleanup-pending', message: 'Cleanup needs retry' }] }
    throw new Error(method)
  })
  const refresh = button(page.render(), 'Refresh').props.onClick()
  await page.flush()
  find(page.render(), 'HostsTab').props.onEdit(host)
  await find(page.render(), 'HostFormModal').props.onSave({ ...host, host: 'new.example' })
  oldRefresh.resolve(state())
  await refresh
  assert.equal(find(page.render(), 'HostsTab').props.state.hosts[0].host, 'new.example')
  assert.ok(nodes(page.render()).some(node => node.type?.name === 'Banner' && text(node).includes('Cleanup needs retry')))
})

test('client: out-of-order reads discard stale data and stale failures', async () => {
  const first = deferred(), second = deferred(); let reads = 0
  const { page } = await ready(() => ++reads === 1 ? state() : reads === 2 ? first.promise : second.promise)
  const a = button(page.render(), 'Refresh').props.onClick(); await page.flush()
  // Invoke the actual callback while a previous request is pending.
  const b = button(page.render(), 'Refreshing…').props.onClick(); await page.flush()
  second.resolve(state('latest.example')); await b
  first.reject(new Error('stale failure')); await a
  assert.equal(find(page.render(), 'HostsTab').props.state.hosts[0].host, 'latest.example')
  assert.ok(!text(page.render()).includes('stale failure'))
})

test('client: mutations serialize; cleanup retry uses host.cleanup and hides credential references', async () => {
  const saved = deferred(), calls = []
  const initial = state('old.example', { pendingCleanup: [{ id: host.id, name: 'web', credentialRef: 'DO_NOT_RENDER' }] })
  const { page } = await ready((method, payload) => {
    calls.push({ method, payload })
    if (method === 'host.save') return saved.promise
    if (method === 'host.cleanup') return { state: state('new.example'), warnings: [] }
    return initial
  })
  assert.ok(!text(page.render()).includes('DO_NOT_RENDER'))
  find(page.render(), 'HostsTab').props.onEdit(host)
  const save = find(page.render(), 'HostFormModal').props.onSave({ ...host, host: 'new.example' })
  await page.flush()
  const cleanup = button(page.render(), 'Retry cleanup').props.onClick()
  await page.flush()
  assert.equal(calls.filter(call => call.method === 'host.cleanup').length, 0)
  saved.resolve({ state: state('new.example', { pendingCleanup: initial.pendingCleanup }) })
  await save; await cleanup
  assert.deepEqual(calls.filter(call => call.method !== 'state').map(call => call.method), ['host.save', 'host.cleanup'])
  assert.deepEqual(calls.find(call => call.method === 'host.cleanup').payload, { id: host.id })
  assert.equal(find(page.render(), 'HostsTab').props.state.pendingCleanup.length, 0)
})

test('client: every settings mutation invalidates an older refresh', async t => {
  for (const method of ['host.delete', 'knownHost.forget', 'knownHost.approve', 'session.close', 'session.closeAll']) {
    await t.test(method, async () => {
      const old = deferred(); let reads = 0
      const initial = state('old.example', {
        knownHosts: [{ host: 'old.example', port: 22, fingerprint: 'SHA256:old' }],
        sessions: [{ key: 'session-key', label: 'deploy' }],
      })
      const { page } = await ready(called => {
        if (called === 'state') return ++reads === 1 ? initial : old.promise
        assert.equal(called, method)
        return { state: state('changed.example'), removed: true, closed: 1 }
      })
      const refresh = button(page.render(), 'Refresh').props.onClick(); await page.flush()
      let operation
      if (method === 'host.delete') {
        find(page.render(), 'HostsTab').props.onDelete(host)
      } else if (method === 'knownHost.approve') {
        find(page.render(), 'HostsTab').props.onEdit(host)
        operation = find(page.render(), 'HostFormModal').props.onApprove({ host: 'old.example', port: 22, fingerprint: 'SHA256:new' })
      } else if (method === 'knownHost.forget') {
        find(page.render(), 'Tabs').props.onChange('knownHosts')
        find(page.render(), 'KnownHostsTab').props.onForget(initial.knownHosts[0])
      } else {
        find(page.render(), 'Tabs').props.onChange('sessions')
        const tab = find(page.render(), 'SessionsTab')
        if (method === 'session.close') tab.props.onCloseSession(initial.sessions[0])
        else tab.props.onCloseAll()
      }
      if (!operation) operation = find(page.render(), 'ConfirmDialog').props.run()
      await operation
      old.resolve(initial); await refresh
      const tab = nodes(page.render()).find(node => ['HostsTab', 'KnownHostsTab', 'SessionsTab'].includes(node.type?.name))
      assert.equal(tab.props.state.hosts[0].host, 'changed.example')
    })
  }
})

test('client: host list test completing after save cannot restore stale trust results', async () => {
  const tested = deferred()
  const { page } = await ready(method => {
    if (method === 'host.test') return tested.promise
    if (method === 'host.save') return { state: state('new.example') }
    return state()
  })
  const running = find(page.render(), 'HostsTab').props.onTest(host)
  find(page.render(), 'HostsTab').props.onEdit(host)
  await find(page.render(), 'HostFormModal').props.onSave({ ...host, host: 'new.example' })
  tested.resolve({ ok: false, hostKeyStatus: 'changed', target: { host: 'old.example', port: 22 }, fingerprint: 'SHA256:old' })
  await running
  assert.deepEqual(plain(find(page.render(), 'HostsTab').props.tests), {})
})

test('client: successful write remains visible when the next queued write fails', async () => {
  const saving = deferred()
  const { page } = await ready(method => {
    if (method === 'host.save') return saving.promise
    if (method === 'host.cleanup') throw new Error('cleanup failed')
    return state('old.example', { pendingCleanup: [{ id: host.id, name: 'web' }] })
  })
  find(page.render(), 'HostsTab').props.onEdit(host)
  const saved = find(page.render(), 'HostFormModal').props.onSave(host)
  await page.flush()
  const cleanup = button(page.render(), 'Retry cleanup').props.onClick()
  saving.resolve({ state: state('committed.example') })
  await saved; await cleanup
  assert.equal(find(page.render(), 'HostsTab').props.state.hosts[0].host, 'committed.example')
  assert.ok(text(page.render()).includes('cleanup failed'))
})

test('client: a failed mutation does not block the next queued cleanup', async () => {
  const calls = []
  const { page } = await ready((method) => {
    calls.push(method)
    if (method === 'host.save') throw new Error('save rejected')
    if (method === 'host.cleanup') return { state: state(), warnings: [] }
    return state('old.example', { pendingCleanup: [{ id: host.id, name: 'web' }] })
  })
  find(page.render(), 'HostsTab').props.onEdit(host)
  const save = find(page.render(), 'HostFormModal').props.onSave(host)
  const rejected = assert.rejects(save, /save rejected/)
  const cleanup = button(page.render(), 'Retry cleanup').props.onClick()
  await rejected; await cleanup
  assert.deepEqual(calls.filter(method => method !== 'state'), ['host.save', 'host.cleanup'])
  assert.equal(find(page.render(), 'HostsTab').props.state.pendingCleanup.length, 0)
})
