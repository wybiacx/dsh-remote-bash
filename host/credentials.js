/**
 * 凭据存储适配器：密码/私钥口令/sudo 密码放在 DSH 内置凭据库的 records 空间，
 * 地址 remote-bash/<hostId>，kind='grant'，payload 为 JSON 对象。
 * 明文只在 Host 进程内存里出现，永不回传浏览器、也不进模型上下文。
 */
import { errorWithCode, isPlainObject } from './util.js'

/** records 空间地址。 */
export function recordKey(hostId) {
  return `remote-bash/${hostId}`
}

const FIELDS = ['password', 'passphrase', 'privateKey', 'sudoPassword']

function pickSecrets(payload) {
  const result = {}
  for (const field of FIELDS) {
    const value = payload?.[field]
    if (typeof value === 'string' && value.length > 0) result[field] = value
  }
  return result
}

export function createSecretStore({ credentials }) {
  const available = Boolean(credentials && typeof credentials.readRecord === 'function')

  function requireStore() {
    if (!available) {
      throw errorWithCode('credentials-unavailable', 'DSH 凭据服务不可用，无法保存或读取主机密码。')
    }
  }

  async function read(hostId) {
    if (!available) return {}
    let record
    try {
      record = await credentials.readRecord(recordKey(hostId))
    } catch (error) {
      throw errorWithCode('credentials-error', `读取凭据失败：${error?.message ?? error}`)
    }
    if (!record || record.kind !== 'grant') return {}
    const payload = isPlainObject(record.payload) ? record.payload : {}
    return pickSecrets(payload)
  }

  return {
    available() {
      return available
    },
    async read(hostId) {
      return read(hostId)
    },
    async flags(hostId) {
      const secrets = await read(hostId)
      const fields = {}
      for (const field of FIELDS) fields[field] = typeof secrets[field] === 'string' && secrets[field].length > 0
      return {
        available,
        configured: Object.values(fields).some(Boolean),
        fields,
      }
    },
    /**
     * 合并写入：patch 中出现的非空字段覆盖；clear 中列出的字段删除。
     * 全部为空时删除整条 record。
     */
    async write(hostId, patch = {}, { clear = [] } = {}) {
      requireStore()
      const current = await read(hostId)
      const next = { ...current }
      for (const field of FIELDS) {
        if (Object.hasOwn(patch ?? {}, field)) {
          const value = patch[field]
          if (typeof value === 'string' && value.length > 0) next[field] = value
        }
      }
      const clearSet = new Set(Array.isArray(clear) ? clear.filter((field) => FIELDS.includes(field)) : [])
      for (const field of clearSet) delete next[field]
      if (Object.keys(next).length === 0) {
        await this.clear(hostId)
        return
      }
      try {
        await credentials.modifyRecord(recordKey(hostId), async () => ({ kind: 'grant', payload: next }))
      } catch (error) {
        throw errorWithCode('credentials-error', `保存凭据失败：${error?.message ?? error}`)
      }
    },
    async clear(hostId) {
      if (!available) return
      try {
        await credentials.deleteRecord(recordKey(hostId))
      } catch (error) {
        throw errorWithCode('credentials-error', `删除凭据失败：${error?.message ?? error}`)
      }
    },
  }
}
