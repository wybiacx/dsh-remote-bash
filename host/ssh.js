/**
 * SSH 连接与操作：TOFU 主机指纹校验、密码/私钥认证、一次命令执行、SFTP 传输。
 * 所有连接都由调用方负责关闭（client.end() / client.destroy()）。
 */
import { readFile, readdir, lstat, mkdir, rm, mkdtemp, rename, realpath } from 'node:fs/promises'
import crypto from 'node:crypto'
import path from 'node:path'
import ssh2 from 'ssh2'
import { expandHome } from './paths.js'
import { fingerprintOf, keyTypeOf } from './knownhosts.js'
import {
  createByteCollector,
  errorWithCode,
  quoteShell,
  safeUtf8,
  truncateBytes,
} from './util.js'

function mapConnectError(error, context) {
  if (context.verificationError) return context.verificationError
  const level = error?.level
  const where = `${context.host.host}:${context.host.port}`
  if (level === 'client-authentication') {
    return errorWithCode('auth-failed', `认证失败（${context.host.username}@${where}）：${error?.message ?? error}`)
  }
  if (level === 'client-timeout') {
    return errorWithCode('connect-timeout', `连接 ${where} 超时。`)
  }
  return errorWithCode('connect-failed', `连接 ${where} 失败：${error?.message ?? error}`)
}

/** 读取/组装私钥认证参数。 */
async function loadKeyOptions(host, secret) {
  const passphrase = typeof secret?.passphrase === 'string' && secret.passphrase ? secret.passphrase : undefined
  if (typeof secret?.privateKey === 'string' && secret.privateKey.trim()) {
    return { privateKey: secret.privateKey, passphrase }
  }
  if (!host.keyPath) {
    throw errorWithCode(
      'key-not-found',
      `主机 ${host.name} 未配置私钥：请在 Remote Bash 设置页填写私钥文件路径或粘贴私钥内容。`,
    )
  }
  const keyPath = expandHome(host.keyPath)
  let data
  try {
    data = await readFile(keyPath)
  } catch (error) {
    throw errorWithCode('key-not-found', `读取私钥失败：${keyPath}（${error?.code ?? error?.message}）`)
  }
  return { privateKey: data, passphrase }
}

/** TOFU 校验主机密钥。 */
async function verifyHostKey(knownHosts, host, hostKey) {
  const fingerprint = fingerprintOf(hostKey)
  const keyType = keyTypeOf(hostKey)
  return knownHosts.verify({ host: host.host, port: host.port, keyType, fingerprint })
}

/** cwd 的 shell 写法：~ 与 $HOME 需要在远端由 shell 展开，不能整体单引号。 */
function cdTarget(cwd) {
  const value = String(cwd)
  if (value === '~' || value === '$HOME') return '"$HOME"'
  if (value.startsWith('~/')) return `"$HOME"/${quoteShell(value.slice(2))}`
  if (value.startsWith('$HOME/')) return `"$HOME"/${quoteShell(value.slice(6))}`
  return quoteShell(value)
}

/** 密码只保存在 sudoInput；收到随机 sudo 提示后才经 channel stdin 发送。 */
export function buildCommand({ command, cwd, sudo, sudoPassword }) {
  let core = String(command ?? '')
  let sudoInput
  if (sudo) {
    const password = typeof sudoPassword === 'string' ? sudoPassword : ''
    if (/[\r\n\0]/.test(password)) throw errorWithCode('invalid-secret', 'sudo 密码不能包含换行或 NUL。')
    const prompt = `__RB_SUDO_${crypto.randomBytes(24).toString('hex')}__`
    sudoInput = { prompt, password }
    // 非登录 bash -c 避免 profile 在 exec 重定向前读取认证 stdin；不自动加载登录配置。
    // 即便 sudo 的凭据缓存/NOPASSWD 跳过认证，业务命令也不会读到认证输入。
    core = `sudo -S -p ${quoteShell(prompt)} -- bash -c ${quoteShell(`exec </dev/null\n${core}`)}`
  }
  const remoteCommand = cwd ? `cd ${cdTarget(cwd)} && (\n${core}\n)` : core
  return sudoInput ? { remoteCommand, sudoInput } : { remoteCommand }
}

/** 过滤可跨包的 sudo 提示；最多发送一次密码，绝不将其写进 shell 源码。 */
export function createSudoResponder(input, send, emit, fail) {
  const token = input ? Buffer.from(input.prompt) : null
  let pending = Buffer.alloc(0)
  let sent = false
  return {
    push(chunk) {
      if (!token) { emit(chunk); return }
      pending = Buffer.concat([pending, Buffer.from(chunk)])
      let index
      while ((index = pending.indexOf(token)) !== -1) {
        if (index) emit(pending.subarray(0, index))
        pending = pending.subarray(index + token.length)
        if (sent) { fail(errorWithCode('sudo-auth-failed', 'sudo 密码认证失败。')); return }
        if (!input.password) { fail(errorWithCode('sudo-password-missing', 'sudo 请求认证，但未配置 sudo 密码（或登录密码）。')); return }
        sent = true
        try { send(`${input.password}\n`) } catch { fail(errorWithCode('session-lost', '无法发送 sudo 认证输入。')); return }
      }
      // 只保留可能属于跨包提示的后缀，普通输出立即进入有界收集器。
      let keep = Math.min(token.length - 1, pending.length)
      while (keep && !pending.subarray(pending.length - keep).equals(token.subarray(0, keep))) keep -= 1
      if (pending.length > keep) emit(pending.subarray(0, pending.length - keep))
      pending = Buffer.from(pending.subarray(pending.length - keep))
    },
    finish() { if (pending.length) emit(pending); pending = Buffer.alloc(0) },
  }
}

/**
 * 在已连接 client 上执行一条命令（一次性 channel）。
 * 返回 { code, signal, output, truncated, timedOut, aborted }。
 */
export function execChannel(client, { command, sudoInput, timeoutMs = 60000, signal, maxOutputBytes = 32768 } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false
    let timedOut = false
    let aborted = false
    let stream = null
    let responder
    const stdout = createByteCollector(maxOutputBytes)
    const stderr = createByteCollector(maxOutputBytes)

    const cleanup = () => {
      clearTimeout(timer)
      if (signal) signal.removeEventListener?.('abort', onAbort)
    }

    const buildResult = (exitCode, exitSignal) => {
      responder?.finish()
      const out = stdout.finish()
      const err = stderr.finish()
      const parts = [out.buffer]
      if (err.buffer.length > 0) parts.push(Buffer.from('\n[stderr]\n'), err.buffer)
      const capped = truncateBytes(Buffer.concat(parts), maxOutputBytes)
      return {
        code: timedOut || aborted ? null : exitCode,
        signal: exitSignal ?? null,
        output: safeUtf8(capped.buffer),
        truncated: out.truncated || err.truncated || capped.truncated,
        timedOut,
        aborted,
      }
    }

    const settle = (exitCode = null, exitSignal = null) => {
      if (settled) return
      settled = true
      cleanup()
      resolve(buildResult(exitCode, exitSignal))
    }

    const onAbort = () => {
      aborted = true
      try { stream?.signal?.('TERM') } catch { /* server may not support signals */ }
      closeStream()
      settle()
    }

    const closeStream = () => {
      try {
        stream?.close()
      } catch {
        // 已关闭。
      }
    }

    const timer = setTimeout(() => {
      timedOut = true
      try {
        stream?.signal?.('KILL')
      } catch {
        // 某些服务端不支持 channel signal，直接关闭。
      }
      closeStream()
      settle()
    }, timeoutMs)

    if (signal) {
      if (signal.aborted) {
        onAbort()
        return
      }
      signal.addEventListener?.('abort', onAbort, { once: true })
    }

    try {
      client.exec(command, (error, channel) => {
        if (settled) { channel?.destroy?.(); return }
        if (error) {
          settled = true
          cleanup()
          reject(errorWithCode('exec-failed', `远程命令启动失败：${error?.message ?? error}`))
          return
        }
        stream = channel
        let exitCode = null
        let exitSignal = null
        responder = createSudoResponder(sudoInput, (text) => channel.write(text), (chunk) => stderr.push(chunk), (error) => {
          if (settled) return
          settled = true
          cleanup()
          channel.destroy?.()
          reject(error)
        })
        channel.on('data', (chunk) => { if (!settled) stdout.push(chunk) })
        channel.stderr?.on('data', (chunk) => { if (!settled) responder.push(chunk) })
        channel.on('exit', (code, signalName) => {
          exitCode = typeof code === 'number' ? code : null
          exitSignal = signalName ?? null
        })
        channel.on('close', () => settle(exitCode, exitSignal))
        channel.on('error', (channelError) => {
          if (settled) return
          settled = true
          cleanup()
          reject(errorWithCode('exec-failed', `远程命令执行出错：${channelError?.message ?? channelError}`))
        })
        // 普通命令立即 EOF；sudo 仅在提示出现时写认证输入，其子命令自行隔离 stdin。
        try {
          if (!sudoInput) channel.end?.()
        } catch {
          // 忽略。
        }
      })
    } catch (error) {
      if (!settled) {
        settled = true
        cleanup()
        reject(errorWithCode('exec-failed', `远程命令执行失败：${error?.message ?? error}`))
      }
    }
  })
}

/** SSH 客户端工厂。 */
export function createSshClient({ knownHosts, logger = console }) {
  async function connect(host, secret = {}, { timeoutMs = 15000, signal } = {}) {
    if (signal?.aborted) throw errorWithCode('aborted', '连接已取消。')
    const auth = host.auth === 'key' ? 'key' : 'password'
    let authOptions
    if (auth === 'key') {
      authOptions = await loadKeyOptions(host, secret)
    } else {
      const password = typeof secret?.password === 'string' ? secret.password : ''
      if (!password) {
        throw errorWithCode('missing-secret', `主机 ${host.name} 没有保存密码，请在 Remote Bash 设置页配置。`)
      }
      authOptions = { password }
    }

    if (signal?.aborted) throw errorWithCode('aborted', '连接已取消。')
    const client = new ssh2.Client()
    return await new Promise((resolve, reject) => {
      let settled = false
      let verificationError = null
      let hostKeyInfo = null
      let banner = ''

      const onAbort = () => finish(errorWithCode('aborted', '连接已取消。'))
      const timer = setTimeout(() => {
        finish(errorWithCode('connect-timeout', `连接 ${host.host}:${host.port} 超时（${timeoutMs}ms）。`))
      }, timeoutMs)

      const cleanup = () => {
        clearTimeout(timer)
        if (signal) signal.removeEventListener?.('abort', onAbort)
      }

      function finish(error, value) {
        if (settled) return
        settled = true
        cleanup()
        if (error) {
          try {
            client.destroy()
          } catch {
            // 已销毁。
          }
          reject(error)
          return
        }
        resolve(value)
      }

      if (signal) signal.addEventListener?.('abort', onAbort, { once: true })

      client.on('banner', (message) => {
        if (typeof message === 'string') banner = message
      })
      client.on('error', (error) => {
        finish(mapConnectError(error, { host, verificationError }))
      })
      client.on('ready', () => {
        finish(null, {
          client,
          fingerprint: hostKeyInfo?.fingerprint ?? null,
          keyType: hostKeyInfo?.keyType ?? null,
          hostKeyStatus: hostKeyInfo?.status ?? 'known',
          banner,
        })
      })

      const hostVerifier = (key, callback) => {
        verifyHostKey(knownHosts, host, key)
          .then((info) => {
            hostKeyInfo = info
            callback(true)
          })
          .catch((error) => {
            if (!verificationError) verificationError = error
            callback(false)
          })
      }

      const config = {
        host: host.host,
        port: host.port,
        username: host.username,
        readyTimeout: timeoutMs,
        keepaliveInterval: 15000,
        keepaliveCountMax: 3,
        hostVerifier,
        ...authOptions,
      }

      try {
        client.connect(config)
      } catch (error) {
        finish(mapConnectError(error, { host, verificationError }))
      }
    })
  }

  return { connect, exec: execChannel }
}

/** 读取远端 $HOME，接受调用方传入的共享 deadline。 */
export async function remoteHome(client, { timeoutMs = 10000, deadline = Date.now() + timeoutMs, signal } = {}) {
  if (deadline <= Date.now()) throw errorWithCode('timeout', '传输超时。')
  const result = await execChannel(client, { command: 'printf %s "$HOME"', timeoutMs: Math.max(1, deadline - Date.now()), signal, maxOutputBytes: 4096 })
  if (result.aborted) throw errorWithCode('aborted', '传输已取消。')
  if (result.timedOut) throw errorWithCode('timeout', '读取远端 HOME 超时。')
  const home = result.output.trim()
  if (result.code !== 0 || !home) throw errorWithCode('remote-home-failed', '无法读取远端 $HOME。')
  return home
}

export function expandRemotePath(target, home) {
  if (typeof target !== 'string' || !target) return target
  if (target === '~' || target === '$HOME') return home
  if (target.startsWith('~/')) return `${home}${target.slice(1)}`
  if (target.startsWith('$HOME/')) return `${home}${target.slice(5)}`
  return target
}

/** 每次传输的所有阶段共用一个 deadline；取消立即销毁 SFTP 通道。 */
function transferScope({ timeoutMs = 300000, deadline = Date.now() + timeoutMs, signal } = {}) {
  let failure = null
  let sftp = null
  let rejectFailure
  const failed = new Promise((_, reject) => { rejectFailure = reject })
  failed.catch(() => {})
  const stop = () => {
    try { if (sftp?.destroy) sftp.destroy(); else sftp?.end?.() } catch { /* closed */ }
  }
  const abort = (error) => { if (!failure) { failure = error; stop(); rejectFailure(error) } }
  const onAbort = () => abort(errorWithCode('aborted', '传输已取消。'))
  const onError = (error) => abort(errorWithCode('sftp-failed', `SFTP 通道失败：${error.message}`))
  const timer = setTimeout(() => abort(errorWithCode('timeout', '传输超时。')), Math.max(0, deadline - Date.now()))
  signal?.addEventListener('abort', onAbort, { once: true })
  if (signal?.aborted) onAbort()
  const scope = {
    check() {
      if (!failure && Date.now() >= deadline) abort(errorWithCode('timeout', '传输超时。'))
      if (failure) throw failure
    },
    async run(operation) {
      scope.check()
      return Promise.race([Promise.resolve().then(() => { scope.check(); return operation() }), failed])
    },
    attach(value) {
      sftp = value
      sftp.on?.('error', onError)
      if (failure) stop()
      scope.check()
    },
    close() {
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
      // 保留 error handler 直到通道实际关闭，以消费迟到的错误事件。
      stop()
    },
  }
  return scope
}

async function openSftp(client, scope) {
  return scope.run(() => new Promise((resolve, reject) => {
    client.sftp((error, sftp) => {
      if (error) { reject(errorWithCode('sftp-failed', `建立 SFTP 通道失败：${error.message}`)); return }
      try { scope.attach(sftp); resolve(sftp) } catch (error) { reject(error) }
    })
  }))
}

function sftpCall(scope, sftp, method, ...args) {
  return scope.run(() => new Promise((resolve, reject) => {
    sftp[method](...args, (error, value) => error ? reject(error) : resolve(value))
  }))
}

async function remoteLstat(scope, sftp, target) {
  try { return await sftpCall(scope, sftp, 'lstat', target) } catch (error) {
    if (error.code === 2) return null
    throw error
  }
}

function noLink(stats, target) {
  if (stats?.isSymbolicLink?.()) throw errorWithCode('unsafe-path', `拒绝传输符号链接：${target}`)
}

export async function remoteStat(client, target, options = {}) {
  const scope = transferScope(options)
  try {
    const sftp = await openSftp(client, scope)
    const stats = await remoteLstat(scope, sftp, target)
    if (!stats) return null
    noLink(stats, target)
    return { isDirectory: stats.isDirectory(), isFile: stats.isFile(), size: Number(stats.size) || 0 }
  } finally { scope.close() }
}

async function sftpMkdirp(scope, sftp, dir) {
  if (!dir || dir === '.' || dir === '/') return
  let stats = await remoteLstat(scope, sftp, dir)
  if (!stats) {
    await sftpMkdirp(scope, sftp, path.posix.dirname(dir))
    try { await sftpCall(scope, sftp, 'mkdir', dir) } catch (error) {
      // 仅允许确实已被并发创建的目录；权限错误不能被静默忽略。
      stats = await remoteLstat(scope, sftp, dir)
      if (!stats) throw error
    }
    stats ??= await remoteLstat(scope, sftp, dir)
  }
  noLink(stats, dir)
  if (!stats?.isDirectory()) throw errorWithCode('invalid-path', `远端路径不是目录：${dir}`)
}

async function localLstat(scope, target) {
  try { return await scope.run(() => lstat(target)) } catch (error) {
    if (error.code === 'ENOENT') return null
    throw error
  }
}

function safeName(name) {
  if (typeof name !== 'string' || !name || name === '.' || name === '..' || /[\\/\0]/.test(name) || path.win32.isAbsolute(name) || /^[A-Za-z]:/.test(name)) {
    throw errorWithCode('unsafe-path', '远端返回了不安全的文件名。')
  }
  return name
}

function inside(root, target) {
  const relative = path.relative(root, target)
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw errorWithCode('unsafe-path', '下载路径超出目标目录。')
}

async function ensureDirectory(scope, target) {
  let stats = await localLstat(scope, target)
  noLink(stats, target)
  if (!stats) {
    await scope.run(() => mkdir(target, { recursive: true, mode: 0o700 }))
    stats = await localLstat(scope, target)
  }
  noLink(stats, target)
  if (!stats?.isDirectory()) throw errorWithCode('invalid-path', `本地路径不是目录：${target}`)
  return scope.run(() => realpath(target))
}

/** 每个文件下载到同目录私有临时目录，完成后原子替换；失败不截断旧文件。 */
async function atomicGet(scope, sftp, remote, target, root) {
  inside(root, target)
  const parent = path.dirname(target)
  const canonicalParent = await scope.run(() => realpath(parent))
  inside(root, canonicalParent)
  if (canonicalParent !== parent) throw errorWithCode('unsafe-path', '下载目标目录包含符号链接。')
  const old = await localLstat(scope, target)
  noLink(old, target)
  if (old && !old.isFile()) throw errorWithCode('invalid-path', '下载目标不是普通文件。')
  // mkdtemp 必须等待完成后才能清理，避免 timeout race 留下迟到创建的临时目录。
  scope.check()
  const staging = await mkdtemp(path.join(parent, '.rb-download-'))
  const temporary = path.join(staging, 'content')
  try {
    scope.check()
    await sftpCall(scope, sftp, 'fastGet', remote, temporary, { concurrency: 16 })
    const current = await localLstat(scope, target)
    noLink(current, target)
    if (current && !current.isFile()) throw errorWithCode('invalid-path', '下载目标不是普通文件。')
    const checkedParent = await scope.run(() => realpath(parent))
    if (checkedParent !== canonicalParent) throw errorWithCode('unsafe-path', '下载目录在传输期间发生变化。')
    scope.check()
    // 来源由 mkdtemp 创建且名称固定；目标已检查根约束、链接和类型。
    await rename(temporary, target)
  } finally {
    const absolute = path.resolve(staging)
    if (path.dirname(absolute) !== parent || !path.basename(absolute).startsWith('.rb-download-')) throw errorWithCode('unsafe-path', '临时目录校验失败。')
    await rm(absolute, { recursive: true, force: true })
  }
}

export async function upload({ client, localPath, remotePath, timeoutMs = 300000, deadline = Date.now() + timeoutMs, signal } = {}) {
  const scope = transferScope({ deadline, signal })
  try {
    const rootStats = await localLstat(scope, localPath)
    if (!rootStats) throw errorWithCode('local-not-found', `本地路径不存在：${localPath}`)
    noLink(rootStats, localPath)
    const sftp = await openSftp(client, scope)
    let bytes = 0
    const put = async (source, target, stats) => {
      noLink(stats, source)
      if (!stats?.isFile()) throw errorWithCode('invalid-path', `本地路径不是普通文件：${source}`)
      noLink(await remoteLstat(scope, sftp, target), target)
      await sftpCall(scope, sftp, 'fastPut', source, target, { concurrency: 16 })
      bytes += stats.size
    }
    const visit = async (source, target, stats) => {
      noLink(stats, source)
      if (stats.isDirectory()) {
        await sftpMkdirp(scope, sftp, target)
        for (const entry of await scope.run(() => readdir(source, { withFileTypes: true }))) {
          const child = path.join(source, safeName(entry.name))
          await visit(child, path.posix.join(target, entry.name), await localLstat(scope, child))
        }
      } else { await put(source, target, stats) }
    }
    if (rootStats.isDirectory()) await visit(localPath, remotePath, rootStats)
    else {
      const target = remotePath.endsWith('/') ? path.posix.join(remotePath, path.basename(localPath)) : remotePath
      await sftpMkdirp(scope, sftp, path.posix.dirname(target))
      await put(localPath, target, rootStats)
    }
    return { bytes }
  } finally { scope.close() }
}

export async function download({ client, remotePath, localPath, timeoutMs = 300000, deadline = Date.now() + timeoutMs, signal } = {}) {
  const scope = transferScope({ deadline, signal })
  try {
    const sftp = await openSftp(client, scope)
    const stats = await remoteLstat(scope, sftp, remotePath)
    if (!stats) throw errorWithCode('remote-not-found', `远端路径不存在：${remotePath}`)
    noLink(stats, remotePath)
    let bytes = 0
    if (stats.isDirectory()) {
      const root = await ensureDirectory(scope, path.resolve(localPath))
      const visit = async (remoteDir, localDir) => {
        inside(root, localDir)
        const entries = await sftpCall(scope, sftp, 'readdir', remoteDir)
        for (const entry of entries ?? []) {
          if (entry.filename === '.' || entry.filename === '..') continue
          const name = safeName(entry.filename)
          const remoteChild = path.posix.join(remoteDir, name)
          const localChild = path.join(localDir, name)
          inside(root, localChild)
          // 不信任目录列表中的 attrs；传输前重新 lstat，并拒绝链接/特殊文件。
          const child = await remoteLstat(scope, sftp, remoteChild)
          if (!child) throw errorWithCode('remote-not-found', `远端路径不存在：${remoteChild}`)
          noLink(child, remoteChild)
          if (child.isDirectory()) {
            const canonical = await ensureDirectory(scope, localChild)
            inside(root, canonical)
            if (canonical !== localChild) throw errorWithCode('unsafe-path', '下载目录包含符号链接。')
            await visit(remoteChild, canonical)
          } else if (child.isFile()) {
            await atomicGet(scope, sftp, remoteChild, localChild, root)
            bytes += Number(child.size) || 0
          } else { throw errorWithCode('unsafe-path', '拒绝下载特殊文件。') }
        }
      }
      await visit(remotePath, root)
    } else if (stats.isFile()) {
      const destination = path.resolve(localPath)
      noLink(await localLstat(scope, destination), destination)
      // 调用方明确选择的父路径可含操作系统别名（如 macOS /var）；先规范化，随后固定此根。
      const root = await ensureDirectory(scope, path.dirname(destination))
      await atomicGet(scope, sftp, remotePath, path.join(root, path.basename(destination)), root)
      bytes = Number(stats.size) || 0
    } else { throw errorWithCode('unsafe-path', '拒绝下载特殊文件。') }
    return { bytes }
  } finally { scope.close() }
}
