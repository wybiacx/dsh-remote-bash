/**
 * 持久会话管理：每个 (agent, label, host) 复用一条 SSH 连接 + 一个 bash。
 * 会话只存在 Host 进程内存里；插件卸载、空闲超时、连接丢失都会关闭。
 */
import { errorWithCode, nowMs } from './util.js'
import { openShell } from './shell.js'
import { buildCommand } from './ssh.js'

const MAX_SESSIONS = 64

export function createSessionManager({ ssh, config, logger = console }) {
  const sessions = new Map()
  const idleMs = Math.max(1, config.sessionIdleMinutes || 30) * 60000

  function keyOf(agentId, label, hostId) {
    return `${agentId}::${label}::${hostId}`
  }

  function info(session) {
    return {
      key: session.key,
      label: session.label,
      hostId: session.hostId,
      hostName: session.hostName,
      agentId: session.agentId,
      createdAt: session.createdAt,
      lastUsedAt: session.lastUsedAt,
    }
  }

  async function removeSession(key) {
    const session = sessions.get(key)
    if (!session) return false
    sessions.delete(key)
    try {
      await session.shell.close()
    } catch {
      // 已关闭。
    }
    try {
      session.client.end()
    } catch {
      // 已结束。
    }
    return true
  }

  async function createSession({ key, label, host, secret, agentId, signal }) {
    const connection = await ssh.connect(host, secret, { timeoutMs: 20000, signal })
    let shell
    try {
      shell = await openShell(connection.client, { timeoutMs: 20000 })
    } catch (error) {
      try {
        connection.client.end()
      } catch {
        // 已结束。
      }
      throw error
    }
    const session = {
      key,
      label,
      hostId: host.id,
      hostName: host.name,
      agentId,
      client: connection.client,
      shell,
      createdAt: nowMs(),
      lastUsedAt: nowMs(),
      fingerprint: connection.fingerprint,
      keyType: connection.keyType,
      hostKeyStatus: connection.hostKeyStatus,
    }
    sessions.set(key, session)
    return session
  }

  async function getOrCreate({ agentId, label, host, secret, signal }) {
    const key = keyOf(agentId, label, host.id)
    const existing = sessions.get(key)
    if (existing && existing.shell.alive) return existing
    if (existing) await removeSession(key)
    if (sessions.size >= MAX_SESSIONS) {
      const oldest = [...sessions.values()].sort((a, b) => a.lastUsedAt - b.lastUsedAt)[0]
      if (oldest) await removeSession(oldest.key)
    }
    return createSession({ key, label, host, secret, agentId, signal })
  }

  // 空闲回收。定时器不阻止 Host 进程退出。
  const sweeper = setInterval(() => {
    const deadline = nowMs() - idleMs
    for (const session of [...sessions.values()]) {
      if (session.lastUsedAt < deadline) {
        void removeSession(session.key).catch((error) => {
          logger.warn?.(`[remote-bash] 关闭空闲会话失败：${error?.message ?? error}`)
        })
      }
    }
  }, 60000)
  sweeper.unref?.()

  return {
    keyOf,
    info,

    async run({
      agentId,
      label,
      host,
      secret,
      command,
      cwd,
      sudo,
      sudoPassword,
      timeoutMs = 60000,
      maxOutputBytes = 32768,
      signal,
    }) {
      if (signal?.aborted) throw errorWithCode('aborted', '执行已取消。')
      const session = await getOrCreate({ agentId, label, host, secret, signal })
      const { remoteCommand } = buildCommand({ command, cwd, sudo, sudoPassword })
      try {
        const result = await session.shell.run(remoteCommand, { timeoutMs, maxOutputBytes })
        session.lastUsedAt = nowMs()
        const meta = {
          sessionKey: session.key,
          fingerprint: session.fingerprint,
          keyType: session.keyType,
          hostKeyStatus: session.hostKeyStatus,
        }
        if (result.timedOut) {
          await removeSession(session.key)
          return { ...result, ...meta, sessionClosed: true }
        }
        return { ...result, ...meta }
      } catch (error) {
        await removeSession(session.key)
        if (error?.code === 'session-closed' || error?.code === 'session-lost') {
          throw errorWithCode('session-lost', '持久会话已断开，请重试（会自动重新连接）。')
        }
        throw error
      }
    },

    list({ agentId } = {}) {
      const all = [...sessions.values()]
      const filtered = agentId ? all.filter((session) => session.agentId === agentId) : all
      return filtered.map(info)
    },

    async close(key) {
      return removeSession(key)
    },

    async closeAll() {
      const keys = [...sessions.keys()]
      await Promise.all(keys.map((key) => removeSession(key)))
      return keys.length
    },

    size() {
      return sessions.size
    },

    dispose() {
      clearInterval(sweeper)
      void this.closeAll()
    },
  }
}
