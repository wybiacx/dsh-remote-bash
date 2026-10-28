/** Credential records are referenced explicitly; secrets never enter inventory data. */
import crypto from 'node:crypto'
import { errorWithCode, isPlainObject } from './util.js'

/** Legacy host-id address, retained for v1 inventories and callers. */
export function recordKey(hostId) {
  return `remote-bash/${hostId}`
}

export function isManagedCredentialRef(ref) {
  return typeof ref === 'string' && (
    /^remote-bash\/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$/.test(ref)
    || /^remote-bash\/refs\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(ref)
  )
}

function requireRef(ref) {
  if (!isManagedCredentialRef(ref)) throw errorWithCode('invalid-credential-ref', '拒绝访问不属于 Remote Bash 的凭据。')
  return ref
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

function mergeSecrets(current, patch, clear) {
  const next = pickSecrets(current)
  for (const field of FIELDS) {
    const value = patch?.[field]
    if (Object.hasOwn(patch ?? {}, field) && typeof value === 'string' && value.length > 0) next[field] = value
  }
  for (const field of Array.isArray(clear) ? clear : []) {
    if (FIELDS.includes(field)) delete next[field]
  }
  return next
}

function payloadOf(record) {
  return record?.kind === 'grant' && isPlainObject(record.payload) ? record.payload : {}
}

export function createSecretStore({ credentials }) {
  const available = Boolean(credentials && typeof credentials.readRecord === 'function')
  function requireStore() {
    if (!available) throw errorWithCode('credentials-unavailable', 'DSH 凭据服务不可用，无法保存或读取主机密码。')
  }
  async function readRef(ref) {
    if (ref == null) return {}
    requireRef(ref)
    if (!available) return {}
    try {
      return pickSecrets(payloadOf(await credentials.readRecord(ref)))
    } catch (error) {
      throw errorWithCode('credentials-error', `读取凭据失败：${error?.message ?? error}`)
    }
  }
  async function flagsRef(ref) {
    const secrets = await readRef(ref)
    const fields = Object.fromEntries(FIELDS.map((field) => [field, Boolean(secrets[field])]))
    return { available, configured: Object.values(fields).some(Boolean), fields }
  }
  async function clearRef(ref) {
    if (ref == null) return
    requireRef(ref)
    requireStore()
    try {
      await credentials.deleteRecord(ref)
    } catch (error) {
      throw errorWithCode('credentials-error', `删除凭据失败：${error?.message ?? error}`)
    }
  }
  const createRef = () => `remote-bash/refs/${crypto.randomUUID()}`
  return {
    available: () => available,
    createRef,
    readRef,
    flagsRef,
    clearRef,
    /** Stage a complete merged snapshot in a fresh record; caller journals ref first. */
    async stage(baseRef, patch = {}, { clear = [], ref = createRef() } = {}) {
      requireStore()
      requireRef(ref)
      if (!ref.startsWith('remote-bash/refs/') || ref === baseRef) {
        throw errorWithCode('invalid-credential-ref', '暂存凭据必须使用新的独立引用。')
      }
      const next = mergeSecrets(await readRef(baseRef), patch, clear)
      if (Object.keys(next).length === 0) return null
      try {
        await credentials.modifyRecord(ref, async (current) => {
          if (current !== undefined) throw errorWithCode('credential-ref-conflict', '暂存凭据引用已存在。')
          return { kind: 'grant', payload: next }
        })
      } catch (error) {
        throw errorWithCode(error?.code === 'credential-ref-conflict' ? error.code : 'credentials-error', `保存凭据失败：${error?.message ?? error}`)
      }
      return ref
    },
    read: (hostId) => readRef(recordKey(hostId)),
    flags: (hostId) => flagsRef(recordKey(hostId)),
    /** Merge inside the provider's exclusive callback, including field clears. */
    async write(hostId, patch = {}, { clear = [] } = {}) {
      requireStore()
      const ref = requireRef(recordKey(hostId))
      try {
        await credentials.modifyRecord(ref, async (current) => ({
          kind: 'grant',
          // An empty grant is intentional: deleteRecord cannot join this transaction.
          payload: mergeSecrets(payloadOf(current), patch, clear),
        }))
      } catch (error) {
        throw errorWithCode('credentials-error', `保存凭据失败：${error?.message ?? error}`)
      }
    },
    async clear(hostId) {
      if (!available) return
      return clearRef(recordKey(hostId))
    },
  }
}
