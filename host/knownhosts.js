/**
 * SSH 主机指纹 TOFU 存储（known_hosts.json）。
 * 指纹格式与 OpenSSH 一致：SHA256: + base64(sha256(host key blob))，去掉 '=' 填充。
 */
import crypto from 'node:crypto'
import ssh2 from 'ssh2'
import { readJsonFile, writeJsonFile, nowMs, errorWithCode } from './util.js'

/** 计算 OpenSSH 风格的 SHA256 指纹。 */
export function fingerprintOf(hostKey) {
  const buffer = Buffer.isBuffer(hostKey) ? hostKey : Buffer.from(hostKey)
  const digest = crypto.createHash('sha256').update(buffer).digest('base64').replace(/=+$/g, '')
  return `SHA256:${digest}`
}

/** 从 host key blob 解析密钥类型（ssh-ed25519 / rsa-sha2-256 ...）。 */
export function keyTypeOf(hostKey) {
  try {
    const parsed = ssh2.utils.parseKey(hostKey)
    const key = Array.isArray(parsed) ? parsed.find((entry) => entry && !(entry instanceof Error)) : parsed
    if (!key || key instanceof Error) return 'unknown'
    return typeof key.type === 'string' && key.type ? key.type : 'unknown'
  } catch {
    return 'unknown'
  }
}

function hostKey(host, port) {
  return `${String(host ?? '').toLowerCase()}:${Number(port) || 22}`
}

function normalizeEntry(raw) {
  if (!raw || typeof raw !== 'object') return null
  const host = typeof raw.host === 'string' ? raw.host.trim() : ''
  const port = Number(raw.port)
  const fingerprint = typeof raw.fingerprint === 'string' ? raw.fingerprint.trim() : ''
  if (!host || !fingerprint) return null
  return {
    host,
    port: Number.isInteger(port) && port > 0 ? port : 22,
    keyType: typeof raw.keyType === 'string' && raw.keyType ? raw.keyType : 'unknown',
    fingerprint,
    firstSeenAt: Number.isFinite(raw.firstSeenAt) ? raw.firstSeenAt : nowMs(),
    lastSeenAt: Number.isFinite(raw.lastSeenAt) ? raw.lastSeenAt : nowMs(),
  }
}

/** 已知主机存储。 */
export function createKnownHosts({ filePath }) {
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
    const hosts = Array.isArray(data?.hosts) ? data.hosts.map(normalizeEntry).filter(Boolean) : []
    cache = { version: 1, hosts }
    return cache
  }

  async function persist(hosts) {
    const document = { version: 1, hosts }
    await writeJsonFile(filePath, document)
    cache = document
  }

  return {
    async list() {
      return serialize(async () => structuredClone((await load()).hosts))
    },
    async find(host, port) {
      return serialize(async () => {
        const state = await load()
        const found = state.hosts.find((entry) => hostKey(entry.host, entry.port) === hostKey(host, port))
        return found ? structuredClone(found) : undefined
      })
    },
    /** 校验与首次提交共享同一临界区，不能在外部先 find 再 record。 */
    async verify({ host, port, keyType, fingerprint }) {
      return serialize(async () => {
        const state = await load()
        const key = hostKey(host, port)
        const existing = state.hosts.find((entry) => hostKey(entry.host, entry.port) === key)
        if (existing && existing.fingerprint !== fingerprint) {
          throw errorWithCode('host-key-changed',
            `主机 ${host}:${port} 的 SSH 指纹与已记录不一致，已拒绝连接。请在设置页核对新指纹。`,
            { host, port, fingerprint, keyType, previousFingerprint: existing.fingerprint })
        }
        const stamp = nowMs()
        const entry = existing
          ? { ...existing, lastSeenAt: stamp }
          : { host: String(host).trim(), port: Number(port) || 22, keyType: keyType || 'unknown', fingerprint, firstSeenAt: stamp, lastSeenAt: stamp }
        const next = existing ? state.hosts.map((item) => item === existing ? entry : item) : [...state.hosts, entry]
        if (existing) {
          try { await persist(next) } catch { /* 刷新时间失败不改变已确认的信任。 */ }
        } else {
          await persist(next)
        }
        return { fingerprint, keyType: entry.keyType, status: existing ? 'known' : 'new' }
      })
    },
    /** 首次记录/刷新已有指纹（不覆盖已存在但不同的指纹）。 */
    async record({ host, port, keyType, fingerprint }) {
      return serialize(async () => {
        const state = await load()
        const stamp = nowMs()
        const key = hostKey(host, port)
        const existing = state.hosts.find((entry) => hostKey(entry.host, entry.port) === key)
        if (existing) {
          const updated = { ...existing, keyType: keyType || existing.keyType, lastSeenAt: stamp }
          const hosts = state.hosts.map((entry) => (entry === existing ? updated : entry))
          await persist(hosts)
          return structuredClone(updated)
        }
        const entry = {
          host: String(host).trim(),
          port: Number(port) || 22,
          keyType: keyType || 'unknown',
          fingerprint,
          firstSeenAt: stamp,
          lastSeenAt: stamp,
        }
        await persist([...state.hosts, entry])
        return structuredClone(entry)
      })
    },
    /** 用户确认新指纹后写入/更新。 */
    async approve({ host, port, keyType, fingerprint }) {
      return serialize(async () => {
        const state = await load()
        const stamp = nowMs()
        const key = hostKey(host, port)
        const existing = state.hosts.find((entry) => hostKey(entry.host, entry.port) === key)
        if (existing) {
          const updated = { ...existing, keyType: keyType || existing.keyType, fingerprint, lastSeenAt: stamp }
          const hosts = state.hosts.map((entry) => (entry === existing ? updated : entry))
          await persist(hosts)
          return structuredClone(updated)
        }
        const entry = {
          host: String(host).trim(),
          port: Number(port) || 22,
          keyType: keyType || 'unknown',
          fingerprint,
          firstSeenAt: stamp,
          lastSeenAt: stamp,
        }
        await persist([...state.hosts, entry])
        return structuredClone(entry)
      })
    },
    async forget(host, port) {
      return serialize(async () => {
        const state = await load()
        const key = hostKey(host, port)
        const hosts = state.hosts.filter((entry) => hostKey(entry.host, entry.port) !== key)
        if (hosts.length === state.hosts.length) return false
        await persist(hosts)
        return true
      })
    },
  }
}
