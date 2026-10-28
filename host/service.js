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
  const testVersions = new Map()
  const trustVersions = new Map()
  const executionPlans = new WeakMap()
  let mutationChain = Promise.resolve()
  let disposed = false
  let disposal
  const lifetime = new AbortController()
  const operations = new Set()

  function assertOpen() {
    if (disposed) throw errorWithCode('aborted', '插件已关闭。')
  }

  function serializeMutation(work) {
    const next = mutationChain.then(() => { assertOpen(); return work() })
    mutationChain = next.catch(() => {})
    return next
  }

  async function withLifetime(signal, work) {
    assertOpen()
    const controller = new AbortController()
    const abort = () => controller.abort()
    const sources = [lifetime.signal, signal].filter(Boolean)
    for (const source of sources) {
      if (source.aborted) controller.abort()
      else source.addEventListener('abort', abort, { once: true })
    }
    const operation = Promise.resolve().then(() => { assertOpen(); return work(controller.signal) })
    operations.add(operation)
    try { return await operation } finally {
      operations.delete(operation)
      for (const source of sources) source.removeEventListener('abort', abort)
    }
  }

  function publicHost(host) {
    const { credentialRef, revision, ...value } = host
    return value
  }

  function refOf(host) {
    return Object.hasOwn(host, 'credentialRef') ? host.credentialRef : `remote-bash/${host.id}`
  }

  async function cleanupPending(id) {
    const warnings = []
    const active = new Set((await inventory.list()).map(refOf).filter(Boolean))
    for (const item of await inventory.listPendingCleanup()) {
      if (id && item.id !== id) continue
      if (active.has(item.ref)) continue
      try {
        await secrets.clearRef(item.ref)
        await inventory.completeCleanup([item.ref])
      } catch {
        warnings.push({ code: 'credential-cleanup-pending', message: `主机 ${item.name || item.id} 的旧凭据尚未清理，可在设置页重试。` })
      }
    }
    return warnings
  }

  const ready = serializeMutation(() => cleanupPending())
  ready.catch((error) => logger.warn?.(`[remote-bash] 恢复清理失败：${error?.code || 'error'}`))

  const timeoutCap = (timeoutSec) => clampInt(timeoutSec, 1, 3600, config.defaultTimeoutSec) * 1000
  const outputCap = (value) => clampInt(value, 1024, 1048576, config.maxOutputBytes)

  async function flagsFor(host) {
    try {
      return await secrets.flagsRef(refOf(host))
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
      ...publicHost(host),
      secret: await flagsFor(host),
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
      pendingCleanup: [...new Map((await inventory.listPendingCleanup()).map(({ id, name }) => [id, { id, name }])).values()],
    }
  }

  async function saveHost(input = {}) {
    await ready
    return serializeMutation(async () => {
      const raw = isPlainObject(input) ? input : {}
      const secretPatch = isPlainObject(raw.secret) ? raw.secret : {}
      const clear = Array.isArray(raw.clear) ? raw.clear : []
      const changesSecrets = Object.values(secretPatch).some((value) => typeof value === 'string' && value.length > 0) || clear.length > 0
      if (changesSecrets && !secrets.available()) {
        throw errorWithCode('credentials-unavailable', 'DSH 凭据服务不可用，无法保存主机密码。')
      }
      const previous = raw.id ? await inventory.get(raw.id) : null
      const prepared = await inventory.prepare({
        id: raw.id, name: raw.name, host: raw.host, port: raw.port, username: raw.username,
        auth: raw.auth, keyPath: raw.keyPath, tags: raw.tags, note: raw.note, sudo: raw.sudo,
      })
      const oldRef = previous ? refOf(previous) : null
      if (changesSecrets) {
        const stagedRef = secrets.createRef()
        // 先登记无秘密的恢复记录，崩溃后可回收尚未提交的新凭据。
        await inventory.queueCleanup([{ ref: stagedRef, id: prepared.id, name: prepared.name }])
        try {
          prepared.credentialRef = await secrets.stage(oldRef, secretPatch, { clear, ref: stagedRef })
        } catch (error) {
          await cleanupPending(prepared.id).catch(() => {})
          throw error
        }
      }
      let host
      try {
        host = await inventory.commitHost(prepared, { retireRefs: oldRef && oldRef !== prepared.credentialRef ? [oldRef] : [] })
      } catch (error) {
        await cleanupPending(prepared.id).catch(() => {})
        throw error
      }
      await sessions.closeHost(host.id)
      if (previous) pendingFingerprints.delete(hostKeyOf(previous.host, previous.port))
      pendingFingerprints.delete(hostKeyOf(host.host, host.port))
      const warnings = await cleanupPending(host.id)
      return { host: { ...publicHost(host), secret: await flagsFor(host) }, warnings, state: await state() }
    })
  }

  async function deleteHost({ id } = {}) {
    if (!id) throw errorWithCode('invalid-host', '缺少主机 id。')
    await ready
    return serializeMutation(async () => {
      const host = await inventory.get(id)
      const pending = (await inventory.listPendingCleanup()).some((entry) => entry.id === id)
      if (!host && !pending) throw errorWithCode('not-found', `主机不存在：${id}`)
      const { removed } = await inventory.removeAndRetire(id)
      await sessions.closeHost(id)
      if (host) pendingFingerprints.delete(hostKeyOf(host.host, host.port))
      const warnings = await cleanupPending(id)
      return { removed: removed || pending, warnings, state: await state() }
    })
  }

  async function cleanupHost({ id } = {}) {
    if (!id) throw errorWithCode('invalid-host', '缺少主机 id。')
    await ready
    return serializeMutation(async () => ({ warnings: await cleanupPending(id), state: await state() }))
  }

  async function testHost({ id, draft, secret, clear = [], signal } = {}) {
    await ready
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
    const storedSecret = stored ? await secrets.readRef(refOf(stored)) : {}
    const overrides = isPlainObject(secret) ? secret : {}
    const merged = { ...storedSecret }
    for (const key of ['password', 'passphrase', 'privateKey', 'sudoPassword']) {
      const value = overrides[key]
      if (typeof value === 'string' && value.length > 0) merged[key] = value
    }
    for (const field of Array.isArray(clear) ? clear : []) {
      if (['password', 'passphrase', 'privateKey', 'sudoPassword'].includes(field)) delete merged[field]
    }
    const target = { host: host.host, port: host.port }
    const testKey = hostKeyOf(host.host, host.port)
    const testVersion = (testVersions.get(testKey) || 0) + 1
    testVersions.set(testKey, testVersion)
    pendingFingerprints.delete(testKey)
    const trustVersion = trustVersions.get(testKey) || 0
    const testIsCurrent = async () => testVersions.get(testKey) === testVersion &&
      (trustVersions.get(testKey) || 0) === trustVersion &&
      (!stored || (await inventory.get(stored.id))?.revision === stored.revision)
    const startedAt = nowMs()
    try {
      const connection = await ssh.connect(host, merged, { timeoutMs: 20000, signal })
      try {
        connection.client.end()
      } catch {
        // 已结束。
      }
      if (!await testIsCurrent()) {
        throw errorWithCode('target-changed', '测试期间主机配置已改变，请重新测试。')
      }
      pendingFingerprints.delete(hostKeyOf(host.host, host.port))
      return {
        target,
        ok: true,
        elapsedMs: nowMs() - startedAt,
        banner: connection.banner || '',
        fingerprint: connection.fingerprint,
        keyType: connection.keyType,
        hostKeyStatus: connection.hostKeyStatus,
      }
    } catch (error) {
      const elapsedMs = nowMs() - startedAt
      if (!await testIsCurrent()) {
        return { ok: false, target, elapsedMs, hostKeyStatus: 'unknown', error: { code: 'target-changed', message: '测试期间主机配置已改变，请重新测试。' } }
      }
      if (error?.code === 'host-key-changed') {
        const details = error.details ?? {}
        pendingFingerprints.set(hostKeyOf(host.host, host.port), {
          fingerprint: details.fingerprint,
          keyType: details.keyType,
          at: nowMs(),
        })
        return {
          ok: false,
          target,
          elapsedMs,
          fingerprint: details.fingerprint,
          keyType: details.keyType,
          hostKeyStatus: 'changed',
          error: { code: 'host-key-changed', message: error.message, details },
        }
      }
      return {
        ok: false,
        target,
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
    await ready
    assertOpen()
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

  function identityOf(host) {
    return JSON.stringify([host.revision, host.host, host.port, host.username, host.auth, host.keyPath, host.sudo, refOf(host)])
  }

  async function prepareRun(options = {}) {
    const command = String(options.command ?? '')
    if (!command.trim()) throw errorWithCode('invalid-command', 'command 不能为空。')
    const hosts = await resolveTargets(options.targets)
    const session = typeof options.session === 'string' && options.session.trim() ? options.session.trim() : undefined
    if (session && !/^[A-Za-z0-9_.-]{1,32}$/.test(session)) {
      throw errorWithCode('invalid-session', 'session 名只能包含字母、数字、点、下划线、连字符，且不超过 32 个字符。')
    }
    const captured = hosts.map((host) => ({
      host: structuredClone(host), identity: identityOf(host),
      trustVersion: trustVersions.get(hostKeyOf(host.host, host.port)) || 0,
      useSudo: options.sudo === undefined ? host.sudo === true : options.sudo === true,
    }))
    const plan = Object.freeze({ hosts: Object.freeze(captured.map(({ host, useSudo }) => Object.freeze({ ...publicHost(host), useSudo }))) })
    executionPlans.set(plan, {
      captured,
      options: { command, session, cwd: typeof options.cwd === 'string' && options.cwd.trim() ? options.cwd.trim() : undefined,
        sudo: options.sudo, timeoutMs: timeoutCap(options.timeoutSec), maxOutputBytes: outputCap(options.maxOutputBytes) },
    })
    return plan
  }

  async function validateTarget(captured) {
    if (disposed) throw errorWithCode('aborted', '插件已关闭。')
    const host = captured.host
    const current = await inventory.get(host.id)
    if (!current || identityOf(current) !== captured.identity ||
      (trustVersions.get(hostKeyOf(host.host, host.port)) || 0) !== captured.trustVersion) {
      throw errorWithCode('target-changed', `主机 ${host.name} 的配置或信任状态已改变，本次未继续执行，请重新发起调用。`)
    }
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
      if (options.signal?.aborted) throw errorWithCode('aborted', '执行已取消。')
      await options.validate()
      const secret = await secrets.readRef(refOf(host))
      const useSudo = options.sudo === undefined ? host.sudo === true : options.sudo === true
      const sudoPassword = useSudo ? secret.sudoPassword || secret.password || '' : undefined
      await options.validate()
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
          validate: options.validate,
        })
        return { ...base, ...summarizeRun(result, startedAt, options.timeoutMs), sessionKey: result.sessionKey }
      }
      const connection = await ssh.connect(host, secret, {
        timeoutMs: Math.min(20000, options.timeoutMs + 5000),
        signal: options.signal,
      })
      let result
      try {
        await options.validate()
        const { remoteCommand, sudoInput } = buildCommand({
          command: options.command,
          cwd: options.cwd,
          sudo: useSudo,
          sudoPassword,
        })
        result = await ssh.exec(connection.client, {
          command: remoteCommand,
          sudoInput,
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

  async function run(args = {}) {
    const plan = args.plan || await prepareRun(args)
    const prepared = executionPlans.get(plan)
    if (!prepared) throw errorWithCode('invalid-plan', '执行计划不存在或已经使用。')
    executionPlans.delete(plan)
    const { captured, options } = prepared
    const startedAt = nowMs()
    const results = await mapLimit(captured, config.maxParallelHosts, (target) =>
      runOne(target.host, {
        ...options,
        agentId: args.agentId,
        signal: args.signal,
        validate: () => validateTarget(target),
      }),
    )
    return {
      command: options.command,
      cwd: options.cwd ?? null,
      session: options.session ?? null,
      sudo: captured.some((target) => target.useSudo),
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
    const deadline = startedAt + timeoutMs
    const base = { hostId: host.id, name: host.name }
    const captured = { host, identity: identityOf(host), trustVersion: trustVersions.get(hostKeyOf(host.host, host.port)) || 0 }
    try {
      if (signal?.aborted) throw errorWithCode('aborted', '传输已取消。')
      await validateTarget(captured)
      const secret = await secrets.readRef(refOf(host))
      const connection = await ssh.connect(host, secret, { timeoutMs: Math.max(1, Math.min(20000, deadline - nowMs())), signal })
      try {
        await validateTarget(captured)
        const home = await remoteHome(connection.client, { deadline, signal })
        if (action === 'upload') {
          const source = resolveLocalPath(applyTemplate(localPath, host))
          const target = expandRemotePath(applyTemplate(remotePath, host), home)
          const result = await upload({ client: connection.client, localPath: source, remotePath: target, timeoutMs, deadline, signal })
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
          const stats = await remoteStat(connection.client, remoteTarget, { deadline, signal })
          if (!stats) throw errorWithCode('remote-not-found', `远端路径不存在：${remoteTarget}`)
          const baseName = path.posix.basename(remoteTarget)
          const hostName = host.name === '.' || host.name === '..' ? host.id : encodeURIComponent(host.name)
          if (stats.isDirectory) {
            if (multi) destination = path.join(destination, hostName)
          } else if (multi) {
            destination = path.join(destination, `${hostName}-${baseName}`)
          } else if (localTemplate.endsWith('/') || await isExistingDirectory(destination)) {
            // 单主机下载文件但 localPath 是目录：落到目录里的同名文件。
            destination = path.join(destination, baseName)
          }
        }
        const result = await download({ client: connection.client, remotePath: remoteTarget, localPath: destination, timeoutMs, deadline, signal })
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

  async function invalidateTrust(host, port) {
    const key = hostKeyOf(host, port)
    trustVersions.set(key, (trustVersions.get(key) || 0) + 1)
    for (const entry of await inventory.list()) {
      if (hostKeyOf(entry.host, entry.port) === key) await sessions.closeHost(entry.id)
    }
  }

  return {
    async state() { await ready; return serializeMutation(state) },
    saveHost,
    deleteHost,
    cleanupHost,
    testHost: (args = {}) => withLifetime(args.signal, (signal) => testHost({ ...args, signal })),
    resolveTargets,
    prepareRun,
    run: (args = {}) => withLifetime(args.signal, (signal) => run({ ...args, signal })),
    upload: (args = {}) => withLifetime(args.signal, (signal) => transfer({ ...args, action: 'upload', signal })),
    download: (args = {}) => withLifetime(args.signal, (signal) => transfer({ ...args, action: 'download', signal })),
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
      await ready
      return serializeMutation(async () => {
        const removed = await knownHosts.forget(host, Number(port) || 22)
        pendingFingerprints.delete(hostKeyOf(host, Number(port) || 22))
        await invalidateTrust(host, Number(port) || 22)
        return { removed, state: await state() }
      })
    },
    async approveFingerprint({ host, port, fingerprint } = {}) {
      if (!host) throw errorWithCode('invalid-host', '缺少主机地址。')
      await ready
      return serializeMutation(async () => {
        const key = hostKeyOf(host, Number(port) || 22)
        const pending = pendingFingerprints.get(key)
        if (!pending) {
          throw errorWithCode('no-pending-fingerprint', '没有待确认的新指纹，请先点「测试连接」触发一次校验。')
        }
        if (!fingerprint || fingerprint !== pending.fingerprint || nowMs() - pending.at > 300000) {
          throw errorWithCode('fingerprint-mismatch', '确认的指纹与最近一次连接看到的新指纹不一致，请重新测试连接。')
        }
        const entry = await knownHosts.approve({
          host,
          port: Number(port) || 22,
          keyType: pending.keyType,
          fingerprint: pending.fingerprint,
        })
        pendingFingerprints.delete(key)
        await invalidateTrust(host, Number(port) || 22)
        return { entry, state: await state() }
      })
    },
    dispose() {
      if (!disposal) {
        disposed = true
        lifetime.abort()
        pendingFingerprints.clear()
        testVersions.clear()
        disposal = Promise.allSettled([sessions.dispose(), mutationChain, ...operations]).then(() => {})
      }
      return disposal
    },
  }
}
