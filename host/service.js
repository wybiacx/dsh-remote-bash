/**
 * Remote Bash 核心服务：主机清单 + 凭据 + SSH 执行 + 持久会话 + SFTP。
 * Agent 工具与浏览器 RPC 共用这一层，保证行为一致。
 */
import path from 'node:path'
import { stat as statLocal } from 'node:fs/promises'
import { normalizeHostInput } from './inventory.js'
import { createSshClient, buildCommand, upload, download, expandRemotePath, remoteHome, remoteStat } from './ssh.js'
import { createSessionManager } from './sessions.js'
import { expandHome } from './paths.js'
import { clampInt, errorWithCode, isPlainObject, mapLimit, nowMs } from './util.js'

function resolveLocalPath(input) {
  const text = String(input ?? '').trim()
  if (!text) throw errorWithCode('invalid-path', '本地路径不能为空。')
  const expanded = expandHome(text)
  if (!expanded) throw errorWithCode('invalid-path', '本地路径不能为空。')
  return path.isAbsolute(expanded) ? expanded : path.resolve(process.cwd(), expanded)
}

function applyTemplate(input, host, extra = {}) {
  return String(input ?? '').replace(/\{(host|name|id|basename)\}/g, (match, key) => {
    if (key === 'host') return host.host
    if (key === 'name') return host.name
    if (key === 'id') return host.id
    if (key === 'basename') return extra.basename ?? ''
    return match
  })
}


async function isExistingDirectory(target) {
  try {
    const stats = await statLocal(target)
    return stats.isDirectory()
  } catch {
    return false
  }
}

function hostKeyOf(host, port) {
  return `${String(host ?? '').toLowerCase()}:${Number(port) || 22}`
}

export function createService({ config, paths, inventory, knownHosts, secrets, approval, logger = console }) {
  const ssh = createSshClient({ knownHosts, logger })
  const sessions = createSessionManager({ ssh, config, logger })
  const pendingFingerprints = new Map()

  const timeoutCap = (timeoutSec) => clampInt(timeoutSec, 1, 3600, config.defaultTimeoutSec) * 1000
  const outputCap = (value) => clampInt(value, 1024, 1048576, config.maxOutputBytes)

  async function flagsFor(hostId) {
    try {
      return await secrets.flags(hostId)
    } catch {
      return {
        available: secrets.available(),
        configured: false,
        fields: { password: false, passphrase: false, privateKey: false, sudoPassword: false },
      }
    }
  }

  async function state() {
    const hosts = await inventory.list()
    const hostStates = await Promise.all(hosts.map(async (host) => ({
      ...host,
      secret: await flagsFor(host.id),
    })))
    const groupMap = new Map()
    for (const host of hostStates) {
      for (const tag of host.tags) {
        if (!groupMap.has(tag)) groupMap.set(tag, [])
        groupMap.get(tag).push(host.id)
      }
    }
    return {
      settings: { ...config, dataDir: paths.root },
      credentialsAvailable: secrets.available(),
      hosts: hostStates,
      groups: [...groupMap.entries()]
        .map(([tag, hostIds]) => ({ tag, hostIds }))
        .sort((a, b) => a.tag.localeCompare(b.tag)),
      knownHosts: await knownHosts.list(),
      sessions: sessions.list(),
    }
  }

  async function saveHost(input = {}) {
    const raw = isPlainObject(input) ? input : {}
    const secretPatch = isPlainObject(raw.secret) ? raw.secret : {}
    const clear = Array.isArray(raw.clear) ? raw.clear : []
    const hasSecretWrite = Object.values(secretPatch).some(
      (value) => typeof value === 'string' && value.length > 0,
    )
    if (hasSecretWrite && !secrets.available()) {
      throw errorWithCode('credentials-unavailable', 'DSH 凭据服务不可用，无法保存主机密码。')
    }
    const host = await inventory.upsert({
      id: raw.id,
      name: raw.name,
      host: raw.host,
      port: raw.port,
      username: raw.username,
      auth: raw.auth,
      keyPath: raw.keyPath,
      tags: raw.tags,
      note: raw.note,
      sudo: raw.sudo,
    })
    if (hasSecretWrite || clear.length > 0) {
      await secrets.write(host.id, secretPatch, { clear })
    }
    return { host: { ...host, secret: await flagsFor(host.id) }, state: await state() }
  }

  async function deleteHost({ id } = {}) {
    if (!id) throw errorWithCode('invalid-host', '缺少主机 id。')
    const host = await inventory.get(id)
    if (!host) throw errorWithCode('not-found', `主机不存在：${id}`)
    const removed = await inventory.remove(id)
    try {
      await secrets.clear(id)
    } catch (error) {
      logger.warn?.(`[remote-bash] 清理主机凭据失败：${error?.message ?? error}`)
    }
    for (const session of sessions.list().filter((entry) => entry.hostId === id)) {
      await sessions.close(session.key)
    }
    return { removed, state: await state() }
  }

  async function testHost({ id, draft, secret } = {}) {
    const hosts = await inventory.list()
    let stored = null
    if (id) {
      stored = hosts.find((entry) => entry.id === id)
      if (!stored) throw errorWithCode('not-found', `主机不存在：${id}`)
    }
    let host
    if (draft !== undefined && isPlainObject(draft)) {
      host = normalizeHostInput(draft, {
        existing: stored,
        others: hosts.filter((entry) => entry.id !== stored?.id),
      })
    } else if (stored) {
      host = stored
    } else {
      throw errorWithCode('invalid-host', '测试连接需要已保存主机 id 或主机草稿。')
    }
    let storedSecret = {}
    if (stored) {
      try {
        storedSecret = await secrets.read(stored.id)
      } catch {
        storedSecret = {}
      }
    }
    const overrides = isPlainObject(secret) ? secret : {}
    const merged = { ...storedSecret }
    for (const key of ['password', 'passphrase', 'privateKey', 'sudoPassword']) {
      const value = overrides[key]
      if (typeof value === 'string' && value.length > 0) merged[key] = value
    }
    const startedAt = nowMs()
    try {
      const connection = await ssh.connect(host, merged, { timeoutMs: 20000 })
      try {
        connection.client.end()
      } catch {
        // 已结束。
      }
      pendingFingerprints.delete(hostKeyOf(host.host, host.port))
      return {
        ok: true,
        elapsedMs: nowMs() - startedAt,
        banner: connection.banner || '',
        fingerprint: connection.fingerprint,
        keyType: connection.keyType,
        hostKeyStatus: connection.hostKeyStatus,
      }
    } catch (error) {
      const elapsedMs = nowMs() - startedAt
      if (error?.code === 'host-key-changed') {
        const details = error.details ?? {}
        pendingFingerprints.set(hostKeyOf(host.host, host.port), {
          fingerprint: details.fingerprint,
          keyType: details.keyType,
          at: nowMs(),
        })
        return {
          ok: false,
          elapsedMs,
          fingerprint: details.fingerprint,
          keyType: details.keyType,
          hostKeyStatus: 'changed',
          error: { code: 'host-key-changed', message: error.message, details },
        }
      }
      return {
        ok: false,
        elapsedMs,
        hostKeyStatus: 'unknown',
        error: { code: error?.code ?? 'error', message: error?.message ?? String(error) },
      }
    }
  }

  function parseTargetTokens(targets) {
    const list = Array.isArray(targets) ? targets : [targets]
    return list
      .flatMap((item) => String(item ?? '').split(/[,，\s]+/))
      .map((token) => token.trim())
      .filter(Boolean)
  }

  async function resolveTargets(targets) {
    const hosts = await inventory.list()
    if (hosts.length === 0) {
      throw errorWithCode('no-hosts', '还没有配置远程主机，请先在 DSH 设置 → Remote Bash 中添加主机。')
    }
    const tokens = parseTargetTokens(targets)
    if (tokens.length === 0) {
      throw errorWithCode('unknown-target', '请指定目标主机：主机名/id、@分组，或 all。')
    }
    const picked = new Map()
    const unknown = []
    for (const token of tokens) {
      if (token.toLowerCase() === 'all') {
        hosts.forEach((host) => picked.set(host.id, host))
        continue
      }
      if (token.startsWith('@')) {
        const tag = token.slice(1).toLowerCase()
        const matched = hosts.filter((host) => host.tags.some((entry) => entry.toLowerCase() === tag))
        if (matched.length === 0) unknown.push(token)
        else matched.forEach((host) => picked.set(host.id, host))
        continue
      }
      const matched = hosts.filter(
        (host) => host.id.toLowerCase() === token.toLowerCase() || host.name.toLowerCase() === token.toLowerCase(),
      )
      if (matched.length === 0) unknown.push(token)
      else matched.forEach((host) => picked.set(host.id, host))
    }
    if (unknown.length > 0) {
      const names = hosts.map((host) => host.name).join('、')
      throw errorWithCode('unknown-target', `找不到目标主机：${unknown.join('、')}。可用主机：${names}`)
    }
    return [...picked.values()]
  }

  function summarizeRun(result, startedAt, timeoutMs) {
    const timedOut = Boolean(result.timedOut)
    const aborted = Boolean(result.aborted)
    const status = timedOut ? 'timeout' : aborted ? 'error' : result.code === 0 ? 'ok' : 'error'
    const summary = {
      status,
      exitCode: result.code ?? null,
      signal: result.signal ?? null,
      output: result.output ?? '',
      truncated: Boolean(result.truncated),
      durationMs: nowMs() - startedAt,
      fingerprint: result.fingerprint ?? null,
      keyType: result.keyType ?? null,
      hostKeyStatus: result.hostKeyStatus ?? null,
    }
    if (timedOut) {
      summary.error = { code: 'timeout', message: `执行超时（${Math.round(timeoutMs / 1000)}s）。` }
    } else if (aborted) {
      summary.error = { code: 'aborted', message: '执行已取消。' }
    }
    return summary
  }

  async function runOne(host, options) {
    const startedAt = nowMs()
    const base = {
      hostId: host.id,
      name: host.name,
      host: host.host,
      port: host.port,
      username: host.username,
    }
    try {
      const secret = await secrets.read(host.id)
      const useSudo = options.sudo === undefined ? host.sudo === true : options.sudo === true
      const sudoPassword = useSudo ? secret.sudoPassword || secret.password || '' : undefined
      if (useSudo && !sudoPassword) {
        throw errorWithCode('sudo-password-missing', `主机 ${host.name} 未配置 sudo 密码。`)
      }
      if (options.session) {
        const result = await sessions.run({
          agentId: options.agentId || 'unknown',
          label: options.session,
          host,
          secret,
          command: options.command,
          cwd: options.cwd,
          sudo: useSudo,
          sudoPassword,
          timeoutMs: options.timeoutMs,
          maxOutputBytes: options.maxOutputBytes,
          signal: options.signal,
        })
        return { ...base, ...summarizeRun(result, startedAt, options.timeoutMs), sessionKey: result.sessionKey }
      }
      const connection = await ssh.connect(host, secret, {
        timeoutMs: Math.min(20000, options.timeoutMs + 5000),
        signal: options.signal,
      })
      let result
      try {
        const { remoteCommand } = buildCommand({
          command: options.command,
          cwd: options.cwd,
          sudo: useSudo,
          sudoPassword,
        })
        result = await ssh.exec(connection.client, {
          command: remoteCommand,
          timeoutMs: options.timeoutMs,
          signal: options.signal,
          maxOutputBytes: options.maxOutputBytes,
        })
      } finally {
        try {
          connection.client.end()
        } catch {
          // 已结束。
        }
      }
      return {
        ...base,
        ...summarizeRun(
          {
            ...result,
            fingerprint: connection.fingerprint,
            keyType: connection.keyType,
            hostKeyStatus: connection.hostKeyStatus,
          },
          startedAt,
          options.timeoutMs,
        ),
      }
    } catch (error) {
      const entry = {
        ...base,
        status: 'error',
        exitCode: null,
        signal: null,
        output: '',
        truncated: false,
        durationMs: nowMs() - startedAt,
        error: { code: error?.code ?? 'error', message: error?.message ?? String(error) },
      }
      if (error?.details?.fingerprint) {
        entry.fingerprint = error.details.fingerprint
        entry.keyType = error.details.keyType
        entry.hostKeyStatus = 'changed'
      }
      return entry
    }
  }

  async function run({
    targets,
    command,
    cwd,
    timeoutSec,
    session,
    sudo,
    maxOutputBytes,
    agentId,
    signal,
  } = {}) {
    const text = String(command ?? '')
    if (!text.trim()) throw errorWithCode('invalid-command', 'command 不能为空。')
    const hosts = await resolveTargets(targets)
    const timeoutMs = timeoutCap(timeoutSec)
    const cap = outputCap(maxOutputBytes)
    const startedAt = nowMs()
    const results = await mapLimit(hosts, config.maxParallelHosts, (host) =>
      runOne(host, {
        command: text,
        cwd: typeof cwd === 'string' && cwd.trim() ? cwd.trim() : undefined,
        timeoutMs,
        maxOutputBytes: cap,
        session: typeof session === 'string' && session.trim() ? session.trim() : undefined,
        sudo,
        agentId,
        signal,
      }),
    )
    return {
      command: text,
      cwd: cwd ?? null,
      session: session ?? null,
      sudo: sudo === true,
      startedAt,
      durationMs: nowMs() - startedAt,
      hosts: results.map((entry) => entry.ok ? entry.value : ({
        hostId: 'unknown',
        name: 'unknown',
        host: '',
        port: 0,
        username: '',
        status: 'error',
        exitCode: null,
        signal: null,
        output: '',
        truncated: false,
        durationMs: 0,
        error: { code: entry.error?.code ?? 'error', message: entry.error?.message ?? String(entry.error) },
      })),
    }
  }

  async function transferHost(host, { action, localPath, remotePath, timeoutMs, signal, multi }) {
    const startedAt = nowMs()
    const base = { hostId: host.id, name: host.name }
    try {
      const secret = await secrets.read(host.id)
      const connection = await ssh.connect(host, secret, { timeoutMs: 20000, signal })
      try {
        const home = await remoteHome(connection.client)
        if (action === 'upload') {
          const source = resolveLocalPath(applyTemplate(localPath, host))
          const target = expandRemotePath(applyTemplate(remotePath, host), home)
          const result = await upload({ client: connection.client, localPath: source, remotePath: target, timeoutMs, signal })
          return { ...base, status: 'ok', bytes: result.bytes, durationMs: nowMs() - startedAt, localPath: source, remotePath: target }
        }
        const remoteTemplate = String(remotePath ?? '')
        const remoteTarget = expandRemotePath(
          applyTemplate(remoteTemplate, host, { basename: path.posix.basename(remoteTemplate) }),
          home,
        )
        const localTemplate = String(localPath ?? '')
        const hasHostToken = /\{(host|name|id)\}/.test(localTemplate)
        let destination = resolveLocalPath(applyTemplate(localTemplate, host, { basename: path.posix.basename(remoteTarget) }))
        if (!hasHostToken) {
          // 多主机下载到同一目录/文件必须区分，否则互相覆盖。
          const stats = await remoteStat(connection.client, remoteTarget)
          if (!stats) throw errorWithCode('remote-not-found', `远端路径不存在：${remoteTarget}`)
          const baseName = path.posix.basename(remoteTarget)
          if (stats.isDirectory) {
            if (multi) destination = path.join(destination, host.name)
          } else if (multi) {
            destination = path.join(destination, `${host.name}-${baseName}`)
          } else if (localTemplate.endsWith('/') || await isExistingDirectory(destination)) {
            // 单主机下载文件但 localPath 是目录：落到目录里的同名文件。
            destination = path.join(destination, baseName)
          }
        }
        const result = await download({ client: connection.client, remotePath: remoteTarget, localPath: destination, timeoutMs, signal })
        return { ...base, status: 'ok', bytes: result.bytes, durationMs: nowMs() - startedAt, localPath: destination, remotePath: remoteTarget }
      } finally {
        try {
          connection.client.end()
        } catch {
          // 已结束。
        }
      }
    } catch (error) {
      return {
        ...base,
        status: 'error',
        bytes: 0,
        durationMs: nowMs() - startedAt,
        error: { code: error?.code ?? 'error', message: error?.message ?? String(error) },
      }
    }
  }

  async function transfer({ action, targets, localPath, remotePath, timeoutSec, signal }) {
    if (!localPath) throw errorWithCode('invalid-path', 'localPath 不能为空。')
    if (!remotePath) throw errorWithCode('invalid-path', 'remotePath 不能为空。')
    const hosts = await resolveTargets(targets)
    const timeoutMs = Math.max(60000, timeoutCap(timeoutSec))
    const startedAt = nowMs()
    const multi = hosts.length > 1
    const results = await mapLimit(hosts, config.maxParallelHosts, (host) =>
      transferHost(host, { action, localPath, remotePath, timeoutMs, signal, multi }),
    )
    return {
      action,
      localPath,
      remotePath,
      durationMs: nowMs() - startedAt,
      hosts: results.map((entry) => entry.ok ? entry.value : ({
        hostId: 'unknown',
        name: 'unknown',
        status: 'error',
        bytes: 0,
        durationMs: 0,
        error: { code: entry.error?.code ?? 'error', message: entry.error?.message ?? String(entry.error) },
      })),
    }
  }

  return {
    state,
    saveHost,
    deleteHost,
    testHost,
    resolveTargets,
    run,
    async upload({ targets, localPath, remotePath, timeoutSec, signal }) {
      return transfer({ action: 'upload', targets, localPath, remotePath, timeoutSec, signal })
    },
    async download({ targets, remotePath, localPath, timeoutSec, signal }) {
      return transfer({ action: 'download', targets, localPath, remotePath, timeoutSec, signal })
    },
    listSessions({ agentId } = {}) {
      return sessions.list({ agentId })
    },
    async closeSession({ key } = {}) {
      if (!key) throw errorWithCode('invalid-session', '缺少会话 key。')
      return sessions.close(key)
    },
    async closeAllSessions() {
      return sessions.closeAll()
    },
    async knownHostsState() {
      return knownHosts.list()
    },
    async forgetKnownHost({ host, port } = {}) {
      if (!host) throw errorWithCode('invalid-host', '缺少主机地址。')
      const removed = await knownHosts.forget(host, Number(port) || 22)
      pendingFingerprints.delete(hostKeyOf(host, Number(port) || 22))
      return { removed, state: await state() }
    },
    async approveFingerprint({ host, port, fingerprint } = {}) {
      if (!host) throw errorWithCode('invalid-host', '缺少主机地址。')
      const key = hostKeyOf(host, Number(port) || 22)
      const pending = pendingFingerprints.get(key)
      if (!pending) {
        throw errorWithCode('no-pending-fingerprint', '没有待确认的新指纹，请先点「测试连接」触发一次校验。')
      }
      if (fingerprint && fingerprint !== pending.fingerprint) {
        throw errorWithCode('fingerprint-mismatch', '确认的指纹与最近一次连接看到的新指纹不一致，请重新测试连接。')
      }
      const entry = await knownHosts.approve({
        host,
        port: Number(port) || 22,
        keyType: pending.keyType,
        fingerprint: pending.fingerprint,
      })
      pendingFingerprints.delete(key)
      return { entry, state: await state() }
    },
    dispose() {
      pendingFingerprints.clear()
      sessions.dispose()
    },
  }
}
