/** 持久会话：同 key 共享创建过程，活动/排队任务不参与空闲回收。 */
import { errorWithCode, nowMs } from './util.js'
import { openShell } from './shell.js'
import { buildCommand } from './ssh.js'

const MAX_SESSIONS = 64

export function createSessionManager({ ssh, config, logger = console }) {
  const sessions = new Map()
  const idleMs = Math.max(1, config.sessionIdleMinutes || 30) * 60000
  let disposed = false
  const keyOf = (agentId, label, hostId) => `${agentId}::${label}::${hostId}`
  const signatureOf = (host) => JSON.stringify([host.host, host.port, host.username, host.auth, host.keyPath, host.revision, host.credentialRef])
  const info = (session) => ({ key: session.key, label: session.label, hostId: session.hostId, hostName: session.hostName, agentId: session.agentId, createdAt: session.createdAt, lastUsedAt: session.lastUsedAt })

  function removeSession(key, expected) {
    const session = sessions.get(key)
    if (!session || (expected && expected !== session)) return false
    sessions.delete(key)
    session.closed = true
    session.controller.abort()
    void session.shell?.close().catch(() => {})
    try { session.client?.destroy?.() } catch { /* closed */ }
    return true
  }

  function reserve({ agentId, label, host, secret }) {
    if (disposed) throw errorWithCode('session-closed', '会话管理器已关闭。')
    const key = keyOf(agentId, label, host.id)
    const existing = sessions.get(key)
    const signature = signatureOf(host)
    if (existing && existing.signature === signature && (!existing.shell || existing.shell.alive)) return existing
    if (existing) removeSession(key, existing)
    if (sessions.size >= MAX_SESSIONS) {
      const oldest = [...sessions.values()].filter((session) => session.shell && session.busy === 0).sort((a, b) => a.lastUsedAt - b.lastUsedAt)[0]
      if (!oldest) throw errorWithCode('session-limit', '持久会话已达上限，且所有会话都在使用中。')
      removeSession(oldest.key, oldest)
    }
    const session = {
      key, signature, label, hostId: host.id, hostName: host.name, agentId,
      createdAt: nowMs(), lastUsedAt: nowMs(), busy: 0, closed: false,
      controller: new AbortController(), client: null, shell: null,
    }
    // 在第一个 await 前预留 key，也将创建中的连接计入容量上限。
    sessions.set(key, session)
    session.ready = (async () => {
      try {
        const connection = await ssh.connect(host, secret, { timeoutMs: 20000, signal: session.controller.signal })
        session.client = connection.client
        if (session.closed || sessions.get(key) !== session) {
          connection.client.destroy?.()
          throw errorWithCode('session-closed', '会话创建期间已被关闭。')
        }
        session.shell = await openShell(connection.client, { timeoutMs: 20000, signal: session.controller.signal })
        if (session.closed || sessions.get(key) !== session) {
          await session.shell.close()
          connection.client.destroy?.()
          throw errorWithCode('session-closed', '会话创建期间已被关闭。')
        }
        session.fingerprint = connection.fingerprint
        session.keyType = connection.keyType
        session.hostKeyStatus = connection.hostKeyStatus
        return session
      } catch (error) {
        removeSession(key, session)
        throw error
      }
    })()
    // 等待者可能全部取消；创建 Promise 仍须有拒绝处理。
    session.ready.catch(() => {})
    return session
  }

  function waitReady(session, signal) {
    if (!signal) return session.ready
    return new Promise((resolve, reject) => {
      const abort = () => { cleanup(); reject(errorWithCode('aborted', '等待持久会话已取消。')) }
      const cleanup = () => signal.removeEventListener('abort', abort)
      if (signal.aborted) { abort(); return }
      signal.addEventListener('abort', abort, { once: true })
      session.ready.then((value) => { cleanup(); resolve(value) }, (error) => { cleanup(); reject(error) })
    })
  }

  function sweepIdle(at = nowMs()) {
    for (const session of sessions.values()) {
      if (session.busy === 0 && session.shell && session.lastUsedAt < at - idleMs) removeSession(session.key, session)
    }
  }
  const sweeper = setInterval(() => {
    try { sweepIdle() } catch (error) { logger.warn?.(`[remote-bash] 空闲会话清理失败：${error.message}`) }
  }, 60000)
  sweeper.unref?.()

  return {
    keyOf, info, sweepIdle,
    async run({ agentId, label, host, secret, command, cwd, sudo, sudoPassword, timeoutMs = 60000, maxOutputBytes = 32768, signal, validate }) {
      if (signal?.aborted) throw errorWithCode('aborted', '执行已取消。')
      const { remoteCommand, sudoInput } = buildCommand({ command, cwd, sudo, sudoPassword })
      const session = reserve({ agentId, label, host, secret })
      session.busy += 1
      try {
        await waitReady(session, signal)
        if (signal?.aborted) throw errorWithCode('aborted', '执行已取消。')
        if (session.closed) throw errorWithCode('session-closed', '会话已关闭。')
        const result = await session.shell.run(remoteCommand, { timeoutMs, maxOutputBytes, sudoInput, signal, validate })
        const meta = { sessionKey: session.key, fingerprint: session.fingerprint, keyType: session.keyType, hostKeyStatus: session.hostKeyStatus }
        if (result.timedOut || result.aborted) {
          removeSession(session.key, session)
          return { ...result, ...meta, sessionClosed: true }
        }
        return { ...result, ...meta }
      } catch (error) {
        if (error?.code === 'target-changed' || (session.shell && !session.shell.alive)) removeSession(session.key, session)
        throw error
      } finally {
        session.busy -= 1
        session.lastUsedAt = nowMs()
        if (session.busy === 0 && !session.shell) removeSession(session.key, session)
      }
    },
    list({ agentId } = {}) {
      return [...sessions.values()].filter((entry) => !agentId || entry.agentId === agentId).map(info)
    },
    async close(key) { return removeSession(key) },
    async closeHost(hostId) {
      let closed = 0
      for (const session of [...sessions.values()]) if (session.hostId === hostId && removeSession(session.key, session)) closed += 1
      return closed
    },
    async closeAll() {
      const keys = [...sessions.keys()]
      for (const key of keys) removeSession(key)
      return keys.length
    },
    size() { return sessions.size },
    dispose() {
      disposed = true
      clearInterval(sweeper)
      for (const key of [...sessions.keys()]) removeSession(key)
    },
  }
}
