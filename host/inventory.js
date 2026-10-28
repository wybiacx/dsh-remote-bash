/**
 * 主机清单（inventory.json）：只存连接信息，永不存密码。
 * 读写串行化，避免 UI 与工具并发改同一文件。
 */
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

/** 主机清单存储。 */
export function createInventory({ filePath }) {
  let cache = null
  let chain = Promise.resolve()

  function serialize(work) {
    const run = chain.then(work)
    chain = run.catch(() => {})
    return run
  }

  async function load() {
    if (cache) return cache
    const data = await readJsonFile(filePath, () => ({ version: 1, hosts: [] }))
    const hosts = Array.isArray(data?.hosts)
      ? data.hosts.map(normalizeStoredHost).filter(Boolean)
      : []
    cache = { version: 1, hosts }
    return cache
  }

  async function persist(nextHosts) {
    const document = { version: 1, hosts: nextHosts }
    await writeJsonFile(filePath, document)
    cache = document
  }

  return {
    async load() {
      return serialize(async () => {
        const state = await load()
        return structuredClone(state)
      })
    },
    async list() {
      return serialize(async () => {
        const state = await load()
        return structuredClone(state.hosts)
      })
    },
    async get(id) {
      return serialize(async () => {
        const state = await load()
        const found = state.hosts.find((entry) => entry.id === id)
        return found ? structuredClone(found) : undefined
      })
    },
    async upsert(input) {
      return serialize(async () => {
        const state = await load()
        const existing = input?.id ? state.hosts.find((entry) => entry.id === input.id) ?? null : null
        const others = state.hosts.filter((entry) => entry.id !== existing?.id)
        const normalized = normalizeHostInput(input, { existing, others })
        const stamp = nowMs()
        const host = existing
          ? { ...normalized, createdAt: existing.createdAt, updatedAt: stamp }
          : { ...normalized, createdAt: stamp, updatedAt: stamp }
        const hosts = existing
          ? state.hosts.map((entry) => (entry.id === host.id ? host : entry))
          : [...state.hosts, host]
        await persist(hosts)
        return structuredClone(host)
      })
    },
    async remove(id) {
      return serialize(async () => {
        const state = await load()
        const hosts = state.hosts.filter((entry) => entry.id !== id)
        if (hosts.length === state.hosts.length) return false
        await persist(hosts)
        return true
      })
    },
  }
}
