import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import { syncBuiltinESMExports } from 'node:module'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { createInventory } from '../host/inventory.js'
import { createSecretStore, recordKey } from '../host/credentials.js'

const hostInput = (overrides = {}) => ({ name: 'web', host: 'old.example', username: 'deploy', auth: 'password', ...overrides })

async function fixture(t) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'rb-storage-'))
  const filePath = path.join(root, 'inventory.json')
  t.after(async () => {
    assert.equal(path.dirname(root), path.resolve(os.tmpdir()))
    assert.ok(path.basename(root).startsWith('rb-storage-'))
    await fs.rm(root, { recursive: true, force: true })
  })
  return { root, filePath, inventory: createInventory({ filePath }) }
}

function credentialProvider(initial = []) {
  const records = new Map(initial)
  const locks = new Map()
  const provider = {
    records, failWrite: false, failDelete: false, deleteCalls: [],
    readRecord: async (ref) => structuredClone(records.get(ref)),
    modifyRecord(ref, mutate) {
      const work = (locks.get(ref) ?? Promise.resolve()).then(async () => {
        const next = await mutate(structuredClone(records.get(ref)))
        if (provider.failWrite) throw new Error('injected credential write failure')
        if (next !== undefined) records.set(ref, structuredClone(next))
        return structuredClone(records.get(ref))
      })
      locks.set(ref, work.catch(() => {}))
      return work
    },
    async deleteRecord(ref) {
      provider.deleteCalls.push(ref)
      if (provider.failDelete) throw new Error('injected credential delete failure')
      records.delete(ref)
    },
  }
  return provider
}

async function commitWithSecret(inventory, secrets, input = hostInput(), patch = { password: 'dummy-old' }) {
  const prepared = await inventory.prepare(input)
  const ref = secrets.createRef()
  await inventory.queueCleanup([{ ref, id: prepared.id, name: prepared.name }])
  const credentialRef = await secrets.stage(prepared.credentialRef, patch, { ref })
  return inventory.commitHost({ ...prepared, credentialRef }, { retireRefs: [prepared.credentialRef] })
}

test('storage: v1 reads preserve ids and legacy refs; first write creates a secret-free backup', async (t) => {
  const { filePath } = await fixture(t)
  const old = { version: 1, hosts: [{ ...hostInput(), id: 'web', password: 'must-not-be-backed-up', secret: { privateKey: 'private' } }] }
  await fs.writeFile(filePath, JSON.stringify(old))
  const inventory = createInventory({ filePath })
  assert.equal((await inventory.get('web')).credentialRef, 'remote-bash/web')
  assert.equal((await inventory.load()).version, 2)
  assert.equal(JSON.parse(await fs.readFile(filePath, 'utf8')).version, 1, 'read must not migrate on disk')
  await assert.rejects(fs.stat(inventory.backupPath), { code: 'ENOENT' })
  await inventory.upsert({ id: 'web', name: 'renamed' })
  const backup = await fs.readFile(inventory.backupPath, 'utf8')
  assert.equal(JSON.parse(backup).hosts[0].id, 'web')
  assert.ok(!backup.includes('must-not-be-backed-up'))
  assert.ok(!backup.includes('private'))
  assert.equal((await fs.stat(inventory.backupPath)).mode & 0o777, 0o600)
  assert.equal((await fs.stat(filePath)).mode & 0o777, 0o600)
  assert.equal((await createInventory({ filePath }).get('web')).credentialRef, 'remote-bash/web')
  await inventory.upsert({ id: 'web', name: 'renamed-again' })
  assert.equal(await fs.readFile(inventory.backupPath, 'utf8'), backup)
})

test('storage: unknown future versions are rejected without rewriting or backup', async (t) => {
  const { filePath, inventory } = await fixture(t)
  const original = JSON.stringify({ version: 99, hosts: [], future: true })
  await fs.writeFile(filePath, original)
  await assert.rejects(inventory.list(), { code: 'unsupported-inventory-version' })
  await assert.rejects(inventory.upsert(hostInput()), { code: 'unsupported-inventory-version' })
  assert.equal(await fs.readFile(filePath, 'utf8'), original)
  await assert.rejects(fs.stat(inventory.backupPath), { code: 'ENOENT' })
})

test('storage: preparing does not commit and recreated names receive fresh identities', async (t) => {
  const { inventory, filePath } = await fixture(t)
  const draft = await inventory.prepare(hostInput())
  assert.match(draft.id, /^web-[0-9a-f-]{36}$/)
  assert.equal(draft.credentialRef, null)
  assert.deepEqual(await inventory.list(), [])
  await assert.rejects(fs.stat(filePath), { code: 'ENOENT' })
  const original = await inventory.commitHost(draft)
  await inventory.removeAndRetire(original.id)
  const recreated = await inventory.upsert(hostInput())
  assert.notEqual(recreated.id, original.id)
  assert.equal(recreated.credentialRef, null)
})

test('storage: commit rejects stale edits, removed records, and duplicate prepared names', async (t) => {
  const { inventory } = await fixture(t)
  const original = await inventory.upsert(hostInput())
  const editA = await inventory.prepare({ id: original.id, username: 'a' })
  const editB = await inventory.prepare({ id: original.id, username: 'b' })
  await inventory.commitHost(editA)
  await assert.rejects(inventory.commitHost(editB), { code: 'inventory-conflict' })
  const stale = await inventory.prepare({ id: original.id, username: 'stale' })
  await inventory.removeAndRetire(original.id)
  await assert.rejects(inventory.commitHost(stale), { code: 'inventory-conflict' })
  const first = await inventory.prepare(hostInput())
  const second = await inventory.prepare(hostInput())
  await inventory.commitHost(first)
  await assert.rejects(inventory.commitHost(second), { code: 'duplicate-name' })
})

test('storage: staged credential activation and retirement share the inventory commit', async (t) => {
  const { inventory, filePath } = await fixture(t)
  const provider = credentialProvider()
  const secrets = createSecretStore({ credentials: provider })
  const original = await commitWithSecret(inventory, secrets)
  const staged = await inventory.prepare({ id: original.id, host: 'new.example' })
  const nextRef = secrets.createRef()
  await inventory.queueCleanup([{ ref: nextRef, id: original.id, name: original.name }])
  await secrets.stage(original.credentialRef, { password: 'dummy-new' }, { ref: nextRef })
  assert.equal((await inventory.get(original.id)).host, 'old.example')
  assert.deepEqual(await secrets.readRef(original.credentialRef), { password: 'dummy-old' })
  await inventory.commitHost({ ...staged, credentialRef: nextRef }, { retireRefs: [original.credentialRef] })
  const reloaded = createInventory({ filePath })
  assert.equal((await reloaded.get(original.id)).credentialRef, nextRef)
  assert.deepEqual(await reloaded.listPendingCleanup(), [{ ref: original.credentialRef, id: original.id, name: original.name }])
  await secrets.clearRef(original.credentialRef)
  await reloaded.completeCleanup([original.credentialRef])
  assert.deepEqual(await createInventory({ filePath }).listPendingCleanup(), [])
  assert.deepEqual(await secrets.readRef(nextRef), { password: 'dummy-new' })
  const persisted = await fs.readFile(filePath, 'utf8')
  assert.ok(!persisted.includes('dummy-old') && !persisted.includes('dummy-new'))
})

test('storage: failed inventory rename preserves live binding and a restart can clean staged ref', async (t) => {
  const { inventory, filePath } = await fixture(t)
  const provider = credentialProvider()
  const secrets = createSecretStore({ credentials: provider })
  const original = await commitWithSecret(inventory, secrets)
  const staged = await inventory.prepare({ id: original.id, host: 'new.example' })
  const ref = secrets.createRef()
  await inventory.queueCleanup([{ ref, id: original.id, name: original.name }])
  await secrets.stage(original.credentialRef, { password: 'dummy-new' }, { ref })
  const rename = fs.rename
  fs.rename = async (from, to) => {
    if (to === filePath) throw Object.assign(new Error('injected inventory rename failure'), { code: 'EIO' })
    return rename(from, to)
  }
  syncBuiltinESMExports()
  try {
    await assert.rejects(inventory.commitHost({ ...staged, credentialRef: ref }, { retireRefs: [original.credentialRef] }), { code: 'EIO' })
  } finally {
    fs.rename = rename
    syncBuiltinESMExports()
  }
  const reloaded = createInventory({ filePath })
  assert.equal((await reloaded.get(original.id)).credentialRef, original.credentialRef)
  assert.deepEqual(await reloaded.listPendingCleanup(), [{ ref, id: original.id, name: original.name }])
  await secrets.clearRef(ref)
  await reloaded.completeCleanup([ref])
  assert.deepEqual(await secrets.readRef(original.credentialRef), { password: 'dummy-old' })
})

test('storage: deletion failure keeps durable retirement and never binds the secret to a recreated host', async (t) => {
  const { inventory, filePath } = await fixture(t)
  const provider = credentialProvider()
  const secrets = createSecretStore({ credentials: provider })
  const original = await commitWithSecret(inventory, secrets)
  await inventory.removeAndRetire(original.id)
  provider.failDelete = true
  await assert.rejects(secrets.clearRef(original.credentialRef), { code: 'credentials-error' })
  const reloaded = createInventory({ filePath })
  assert.equal((await reloaded.listPendingCleanup())[0].ref, original.credentialRef)
  const replacement = await reloaded.upsert(hostInput({ host: 'different.example' }))
  assert.notEqual(replacement.id, original.id)
  assert.deepEqual(await secrets.readRef(replacement.credentialRef), {})
  provider.failDelete = false
  await secrets.clearRef(original.credentialRef)
  await reloaded.completeCleanup([original.credentialRef])
  assert.deepEqual(await createInventory({ filePath }).listPendingCleanup(), [])
})

test('storage: cleanup refuses active refs and records outside the managed namespace', async (t) => {
  const { inventory } = await fixture(t)
  const provider = credentialProvider()
  const secrets = createSecretStore({ credentials: provider })
  const host = await commitWithSecret(inventory, secrets)
  await assert.rejects(inventory.queueCleanup([{ ref: host.credentialRef, id: host.id, name: host.name }]), { code: 'credential-ref-active' })
  for (const ref of ['other-plugin/key', 'remote-bash/../key', 'remote-bash/refs/not-a-uuid']) {
    await assert.rejects(secrets.clearRef(ref), { code: 'invalid-credential-ref' })
    await assert.rejects(secrets.readRef(ref), { code: 'invalid-credential-ref' })
    await assert.rejects(inventory.queueCleanup([{ ref, id: host.id, name: host.name }]), { code: 'invalid-credential-ref' })
  }
  assert.deepEqual(provider.deleteCalls, [])
})

test('storage: concurrent credential adapters merge from the provider current record', async () => {
  const provider = credentialProvider([[recordKey('legacy'), { kind: 'grant', payload: { password: 'old', privateKey: 'old-key' } }]])
  const one = createSecretStore({ credentials: provider })
  const two = createSecretStore({ credentials: provider })
  await Promise.all([
    one.write('legacy', { password: 'new' }, { clear: ['privateKey'] }),
    two.write('legacy', { sudoPassword: 'sudo' }),
  ])
  assert.deepEqual(await one.read('legacy'), { password: 'new', sudoPassword: 'sudo' })
  await Promise.all([
    one.write('legacy', {}, { clear: ['password', 'sudoPassword'] }),
    two.write('legacy', { privateKey: 'new-key' }),
  ])
  assert.deepEqual(await one.read('legacy'), { privateKey: 'new-key' })
  assert.deepEqual(provider.deleteCalls, [], 'field clear must not race a separate deleteRecord')
})

test('storage: failed stages preserve old credentials and cannot overwrite occupied refs', async () => {
  const provider = credentialProvider([[recordKey('legacy'), { kind: 'grant', payload: { password: 'old' } }]])
  const secrets = createSecretStore({ credentials: provider })
  const ref = secrets.createRef()
  provider.failWrite = true
  await assert.rejects(secrets.stage(recordKey('legacy'), { password: 'new' }, { ref }), { code: 'credentials-error' })
  assert.deepEqual(await secrets.read('legacy'), { password: 'old' })
  assert.equal(provider.records.has(ref), false)
  provider.failWrite = false
  assert.equal(await secrets.stage(recordKey('legacy'), {}, { clear: ['password'], ref }), null)
  assert.equal(provider.records.has(ref), false)
  await secrets.stage(recordKey('legacy'), { password: 'new' }, { ref })
  await assert.rejects(secrets.stage(recordKey('legacy'), { password: 'other' }, { ref }), { code: 'credential-ref-conflict' })
  assert.deepEqual(await secrets.readRef(ref), { password: 'new' })
  await assert.rejects(secrets.stage(ref, {}, { ref }), { code: 'invalid-credential-ref' })
})

test('storage: unavailable credential service never reports pending reference cleanup as successful', async () => {
  const secrets = createSecretStore({ credentials: undefined })
  await assert.rejects(secrets.clearRef('remote-bash/legacy'), { code: 'credentials-unavailable' })
  assert.deepEqual(await secrets.readRef(null), {})
})
