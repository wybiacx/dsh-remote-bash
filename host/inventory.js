/**
 * 主机清单（inventory.json）：只存连接信息，永不存密码。
 * 读写串行化，避免 UI 与工具并发改同一文件。
 */
import crypto from 'node:crypto'
import { writeFile } from 'node:fs/promises'
import { isManagedCredentialRef, recordKey } from './credentials.js'
import { readJsonFile, writeJsonFile, nowMs, slugify, uniqueStrings, errorWithCode, isPlainObject } from './util.js'

const AUTH_METHODS = new Set(['password', 'key'])

function toText(value, max = 512) {
  return typeof value === 'string' ? value.trim().slice(0, max) : ''
}

function normalizeTags(value) {
  if (typeof value === 'string') return uniqueStrings(value.split(/[,，\s]+/), { max: 12, maxLength: 32 })
  return uniqueStrings(value, { max: 12, maxLength: 32 })
}

function isHostTextValid(value) {
  // 允许 IPv4/域名/IPv6（可带方括号）与普通主机名；拒绝空白和斜杠。
  return typeof value === 'string' && value.length > 0 && !/[\s/]/.test(value)
}

/** 存储层记录归一（用于读旧数据/缺字段数据）。 */
export function normalizeStoredHost(raw) {
  if (!isPlainObject(raw)) return null
  const id = toText(raw.id, 64)
  if (!id) return null
  return {
    id,
    name: toText(raw.name, 64) || id,
    host: toText(raw.host, 255),
    port: Number.isInteger(raw.port) && raw.port > 0 && raw.port < 65536 ? raw.port : 22,
    username: toText(raw.username, 128),
    auth: AUTH_METHODS.has(raw.auth) ? raw.auth : 'password',
    keyPath: toText(raw.keyPath, 512),
    tags: normalizeTags(raw.tags),
    note: toText(raw.note, 500),
    sudo: raw.sudo === true,
    createdAt: Number.isFinite(raw.createdAt) ? raw.createdAt : nowMs(),
    updatedAt: Number.isFinite(raw.updatedAt) ? raw.updatedAt : nowMs(),
    revision: Number.isSafeInteger(raw.revision) && raw.revision >= 0 ? raw.revision : 0,
    credentialRef: raw.credentialRef ?? null,
  }
}

/**
 * 校验并归一一次保存输入。
 * @param {object} input
 * @param {{ existing?: object|null, others?: object[] }} context
 */
export function normalizeHostInput(input, { existing = null, others = [] } = {}) {
  const raw = isPlainObject(input) ? input : {}
  const name = toText(raw.name ?? existing?.name, 64)
  if (!name) throw errorWithCode('invalid-host', '主机名称必填（1-64 个字符）。')

  if (raw.id !== undefined && raw.id !== null && raw.id !== '' && !existing) {
    throw errorWithCode('not-found', `主机不存在：${raw.id}`)
  }

  const host = toText(raw.host ?? existing?.host, 255)
  if (!isHostTextValid(host)) throw errorWithCode('invalid-host', '主机地址必填，且不能包含空白或斜杠。')

  const portRaw = raw.port ?? existing?.port ?? 22
  const port = Number(portRaw)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw errorWithCode('invalid-host', '端口必须是 1-65535 的整数。')
  }

  const username = toText(raw.username ?? existing?.username, 128)
  if (!username || /\s/.test(username)) throw errorWithCode('invalid-host', '用户名必填，且不能包含空白。')

  const auth = raw.auth ?? existing?.auth ?? 'password'
  if (!AUTH_METHODS.has(auth)) throw errorWithCode('invalid-host', "认证方式只能是 'password' 或 'key'。")

  const keyPath = toText(raw.keyPath ?? existing?.keyPath, 512)
  const tags = raw.tags !== undefined ? normalizeTags(raw.tags) : normalizeTags(existing?.tags)
  const note = toText(raw.note ?? existing?.note, 500)
  const sudo = raw.sudo !== undefined ? raw.sudo === true : existing?.sudo === true

  const nameKey = name.toLowerCase()
  for (const other of others) {
    if (!other || other.id === existing?.id) continue
    if (String(other.name).toLowerCase() === nameKey) {
      throw errorWithCode('duplicate-name', `主机名称已存在：${name}`)
    }
  }

  let id = existing?.id ?? toText(raw.id, 64)
  if (!id) {
    const base = slugify(name)
    let candidate = base
    let index = 2
    const taken = new Set((others ?? []).map((entry) => entry?.id))
    while (taken.has(candidate)) candidate = `${base}-${index++}`
    id = candidate
  }

  return { id, name, host, port, username, auth, keyPath, tags, note, sudo }
}

/** v2 inventory: hosts and the credential cleanup journal commit together. */
export function createInventory({ filePath }) {
  let cache = null
  let legacyBackup = null
  let chain = Promise.resolve()
  const backupPath = `${filePath}.v1.bak`

  function serialize(work) {
    const run = chain.then(work)
    chain = run.catch(() => {})
    return run
  }

  function checkedRef(ref) {
    if (!isManagedCredentialRef(ref)) throw errorWithCode('invalid-credential-ref', '清单包含不属于 Remote Bash 的凭据引用。')
    return ref
  }

  function cleanupEntries(entries, hosts) {
    const active = new Set(hosts.map((host) => host.credentialRef).filter(Boolean))
    const result = new Map()
    for (const entry of entries) {
      if (!isPlainObject(entry) || !entry.id || !entry.name) throw errorWithCode('corrupt-data', '待清理凭据记录缺少主机身份。')
      const ref = checkedRef(entry.ref)
      if (active.has(ref)) throw errorWithCode('credential-ref-active', '不能清理正在使用的凭据引用。')
      result.set(ref, { ref, id: String(entry.id), name: String(entry.name) })
    }
    return [...result.values()]
  }

  async function load() {
    if (cache) return cache
    const data = await readJsonFile(filePath, null)
    if (data === null) {
      cache = { version: 2, hosts: [], pendingCleanup: [] }
      return cache
    }
    if (!isPlainObject(data) || !Array.isArray(data.hosts)) throw errorWithCode('corrupt-data', '主机清单格式无效。')
    const version = data.version ?? 1
    if (version !== 1 && version !== 2) throw errorWithCode('unsupported-inventory-version', `不支持主机清单版本 ${version}；原文件未修改。`)
    const hosts = data.hosts.map((raw) => {
      const host = normalizeStoredHost(raw)
      if (!host) throw errorWithCode('corrupt-data', '主机清单包含无效记录。')
      host.credentialRef = version === 1 ? recordKey(host.id) : host.credentialRef
      if (host.credentialRef != null) checkedRef(host.credentialRef)
      return host
    })
    if (new Set(hosts.map((host) => host.id)).size !== hosts.length) throw errorWithCode('corrupt-data', '主机清单包含重复身份。')
    if (version === 2 && !Array.isArray(data.pendingCleanup ?? [])) throw errorWithCode('corrupt-data', '凭据清理日志格式无效。')
    const pendingCleanup = cleanupEntries(version === 1 ? [] : data.pendingCleanup ?? [], hosts)
    if (version === 1) {
      legacyBackup = {
        version: 1,
        hosts: hosts.map(({ credentialRef, revision, ...host }) => host),
      }
    }
    cache = { version: 2, hosts, pendingCleanup }
    return cache
  }

  async function persist(document) {
    if (legacyBackup) {
      try {
        await writeFile(backupPath, `${JSON.stringify(legacyBackup, null, 2)}\n`, { flag: 'wx', mode: 0o600 })
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error
        // Never replace the first migration backup; refuse a broken one.
        const backup = await readJsonFile(backupPath, null)
        if (backup?.version !== 1 || !Array.isArray(backup.hosts)) throw errorWithCode('corrupt-data', '旧版清单备份无效，已停止迁移。')
      }
    }
    await writeJsonFile(filePath, document)
    cache = document
    legacyBackup = null
  }

  async function prepare(input) {
    const state = await load()
    const existing = input?.id ? state.hosts.find((entry) => entry.id === input.id) ?? null : null
    const normalized = normalizeHostInput(input, { existing, others: state.hosts.filter((entry) => entry.id !== existing?.id) })
    const stamp = nowMs()
    return {
      ...normalized,
      id: existing?.id ?? `${slugify(normalized.name).slice(0, 27)}-${crypto.randomUUID()}`,
      createdAt: existing?.createdAt ?? stamp,
      updatedAt: stamp,
      revision: (existing?.revision ?? 0) + 1,
      expectedRevision: existing?.revision ?? null,
      credentialRef: existing?.credentialRef ?? null,
    }
  }

  async function commitHost(prepared, { retireRefs = [] } = {}) {
    const state = await load()
    const existing = state.hosts.find((entry) => entry.id === prepared?.id)
    if (!prepared || !Object.hasOwn(prepared, 'expectedRevision') || (existing?.revision ?? null) !== prepared.expectedRevision) {
      throw errorWithCode('inventory-conflict', '主机记录已经改变，请刷新后重试。')
    }
    const normalized = normalizeHostInput(prepared, { existing: existing ?? prepared, others: state.hosts.filter((entry) => entry.id !== prepared.id) })
    const host = normalizeStoredHost({ ...prepared, ...normalized, revision: (existing?.revision ?? 0) + 1 })
    if (host.credentialRef != null) checkedRef(host.credentialRef)
    if (state.hosts.some((other) => other.id !== host.id && host.credentialRef && other.credentialRef === host.credentialRef)) {
      throw errorWithCode('credential-ref-conflict', '主机不能复用其他主机的凭据引用。')
    }
    const hosts = existing ? state.hosts.map((entry) => entry.id === host.id ? host : entry) : [...state.hosts, host]
    const retired = retireRefs.filter(Boolean).map((ref) => ({ ref, id: host.id, name: host.name }))
    const pending = [...state.pendingCleanup, ...retired].filter((entry) => entry.ref !== host.credentialRef)
    const pendingCleanup = cleanupEntries(pending, hosts)
    await persist({ version: 2, hosts, pendingCleanup })
    return structuredClone(host)
  }

  async function removeAndRetire(id) {
    const state = await load()
    const host = state.hosts.find((entry) => entry.id === id)
    if (!host) return { removed: false, host: undefined }
    const hosts = state.hosts.filter((entry) => entry.id !== id)
    const retired = host.credentialRef ? [{ ref: host.credentialRef, id: host.id, name: host.name }] : []
    const pendingCleanup = cleanupEntries([...state.pendingCleanup, ...retired], hosts)
    await persist({ version: 2, hosts, pendingCleanup })
    return { removed: true, host: structuredClone(host) }
  }

  return {
    backupPath,
    load: () => serialize(async () => structuredClone(await load())),
    list: () => serialize(async () => structuredClone((await load()).hosts)),
    get: (id) => serialize(async () => structuredClone((await load()).hosts.find((host) => host.id === id))),
    prepare: (input) => serialize(() => prepare(input)),
    commitHost: (host, options) => serialize(() => commitHost(host, options)),
    removeAndRetire: (id) => serialize(() => removeAndRetire(id)),
    listPendingCleanup: () => serialize(async () => structuredClone((await load()).pendingCleanup)),
    queueCleanup: (entries) => serialize(async () => {
      const state = await load()
      const pendingCleanup = cleanupEntries([...state.pendingCleanup, ...entries], state.hosts)
      await persist({ ...state, pendingCleanup })
      return structuredClone(pendingCleanup)
    }),
    completeCleanup: (refs) => serialize(async () => {
      const state = await load()
      const completed = new Set(refs.map(checkedRef))
      const pendingCleanup = state.pendingCleanup.filter((entry) => !completed.has(entry.ref))
      if (pendingCleanup.length !== state.pendingCleanup.length) await persist({ ...state, pendingCleanup })
      return structuredClone(pendingCleanup)
    }),
    // Compatibility wrappers; new service transactions use prepare/commit explicitly.
    upsert: (input) => serialize(async () => commitHost(await prepare(input))),
    remove: (id) => serialize(async () => (await removeAndRetire(id)).removed),
  }
}
