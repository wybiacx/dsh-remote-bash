/**
 * SSH 连接与操作：TOFU 主机指纹校验、密码/私钥认证、一次命令执行、SFTP 传输。
 * 所有连接都由调用方负责关闭（client.end() / client.destroy()）。
 */
import { readFile, readdir, stat, mkdir, rm } from 'node:fs/promises'
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
  const existing = await knownHosts.find(host.host, host.port)
  if (!existing) {
    await knownHosts.record({ host: host.host, port: host.port, keyType, fingerprint })
    return { fingerprint, keyType, status: 'new' }
  }
  if (existing.fingerprint === fingerprint) {
    try {
      await knownHosts.record({ host: host.host, port: host.port, keyType, fingerprint })
    } catch {
      // 刷新 lastSeenAt 失败不影响连接。
    }
    return { fingerprint, keyType, status: 'known' }
  }
  throw errorWithCode(
    'host-key-changed',
    `主机 ${host.host}:${host.port} 的 SSH 指纹与已记录不一致，已拒绝连接。请确认新指纹后在 Remote Bash 设置页重新信任。`,
    {
      host: host.host,
      port: host.port,
      fingerprint,
      keyType,
      previousFingerprint: existing.fingerprint,
    },
  )
}

/** cwd 的 shell 写法：~ 与 $HOME 需要在远端由 shell 展开，不能整体单引号。 */
function cdTarget(cwd) {
  const value = String(cwd)
  if (value === '~' || value === '$HOME') return '"$HOME"'
  if (value.startsWith('~/')) return `"$HOME"/${quoteShell(value.slice(2))}`
  if (value.startsWith('$HOME/')) return `"$HOME"/${quoteShell(value.slice(6))}`
  return quoteShell(value)
}

/** 构造 sudo 安全 heredoc 与可选 cwd 包装。密码不会进 argv / ps。 */
export function buildCommand({ command, cwd, sudo, sudoPassword }) {
  let core = String(command ?? '')
  if (sudo) {
    const password = typeof sudoPassword === 'string' ? sudoPassword : ''
    if (!password) {
      throw errorWithCode('sudo-password-missing', 'sudo 执行需要在设置页配置 sudo 密码（或登录密码）。')
    }
    if (password.includes('\n') || password.includes('\r')) {
      throw errorWithCode('invalid-secret', 'sudo 密码不能包含换行。')
    }
    let delimiter = `__RB_SUDO_${Math.random().toString(16).slice(2, 10)}__`
    while (password.includes(delimiter)) delimiter = `__RB_SUDO_${Math.random().toString(16).slice(2, 10)}__`
    core = `sudo -S -p '' -- bash -lc ${quoteShell(core)} <<'${delimiter}'\n${password}\n${delimiter}`
  }
  const remoteCommand = cwd ? `cd ${cdTarget(cwd)} && (\n${core}\n)` : core
  return { remoteCommand }
}

/**
 * 在已连接 client 上执行一条命令（一次性 channel）。
 * 返回 { code, signal, output, truncated, timedOut, aborted }。
 */
export function execChannel(client, { command, timeoutMs = 60000, signal, maxOutputBytes = 32768 } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false
    let timedOut = false
    let aborted = false
    let stream = null
    let fallbackTimer = null
    const stdout = createByteCollector(maxOutputBytes)
    const stderr = createByteCollector(maxOutputBytes)

    const cleanup = () => {
      clearTimeout(timer)
      clearTimeout(fallbackTimer)
      if (signal) signal.removeEventListener?.('abort', onAbort)
    }

    const buildResult = (exitCode, exitSignal) => {
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
      fallbackTimer = setTimeout(() => settle(), 500)
    }, timeoutMs)

    if (signal) {
      if (signal.aborted) {
        settle()
        return
      }
      signal.addEventListener?.('abort', onAbort, { once: true })
    }

    try {
      client.exec(command, (error, channel) => {
        if (settled) return
        if (error) {
          settled = true
          cleanup()
          reject(errorWithCode('exec-failed', `远程命令启动失败：${error?.message ?? error}`))
          return
        }
        stream = channel
        let exitCode = null
        let exitSignal = null
        channel.on('data', (chunk) => stdout.push(chunk))
        channel.stderr?.on('data', (chunk) => stderr.push(chunk))
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
        // 命令不读取客户端 stdin：立即半关闭，避免远端命令挂起等待输入。
        try {
          channel.end?.()
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

/** 读取远端 $HOME。 */
export async function remoteHome(client) {
  const result = await execChannel(client, {
    command: 'printf %s "$HOME"',
    timeoutMs: 10000,
    maxOutputBytes: 4096,
  })
  const home = result.output.trim()
  if (!home) throw errorWithCode('remote-home-failed', '无法读取远端 $HOME。')
  return home
}

/** 展开远端路径里的 ~ / $HOME。 */
export function expandRemotePath(target, home) {
  if (typeof target !== 'string' || !target) return target
  if (target === '~') return home
  if (target.startsWith('~/')) return `${home}${target.slice(1)}`
  if (target.startsWith('$HOME')) return `${home}${target.slice(5)}`
  return target
}

/** 远端路径元信息（文件/目录 + 大小），不存在返回 null。 */
export async function remoteStat(client, target) {
  const sftp = await openSftp(client)
  try {
    const stats = await sftpStat(sftp, target)
    if (!stats) return null
    return { isDirectory: stats.isDirectory(), isFile: stats.isFile(), size: Number(stats.size) || 0 }
  } finally {
    try {
      sftp.end?.()
    } catch {
      // 已关闭。
    }
  }
}

function timeoutError(message = '传输超时。') {
  return errorWithCode('timeout', message)
}

function openSftp(client, { timeoutMs = 15000, signal } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      reject(timeoutError('建立 SFTP 通道超时。'))
    }, timeoutMs)
    const onAbort = () => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      reject(errorWithCode('aborted', '传输已取消。'))
    }
    if (signal) {
      if (signal.aborted) {
        clearTimeout(timer)
        reject(errorWithCode('aborted', '传输已取消。'))
        return
      }
      signal.addEventListener?.('abort', onAbort, { once: true })
    }
    try {
      client.sftp((error, sftp) => {
        if (settled) {
          try {
            sftp?.end?.()
          } catch {
            // 已关闭。
          }
          return
        }
        settled = true
        clearTimeout(timer)
        if (signal) signal.removeEventListener?.('abort', onAbort)
        if (error) reject(errorWithCode('sftp-failed', `建立 SFTP 通道失败：${error?.message ?? error}`))
        else resolve(sftp)
      })
    } catch (error) {
      if (!settled) {
        settled = true
        clearTimeout(timer)
        reject(errorWithCode('sftp-failed', `建立 SFTP 通道失败：${error?.message ?? error}`))
      }
    }
  })
}

function sftpMkdirp(sftp, dir) {
  if (!dir || dir === '.' || dir === '/') return Promise.resolve()
  const isAbsolute = dir.startsWith('/')
  const parts = dir.split('/').filter(Boolean)
  let current = isAbsolute ? '/' : ''
  return parts.reduce(
    (previous, part) => previous.then(() => new Promise((resolve) => {
      current = current === '/' ? `/${part}` : current ? `${current}/${part}` : part
      sftp.mkdir(current, () => resolve())
    })),
    Promise.resolve(),
  )
}

function sftpStat(sftp, target) {
  return new Promise((resolve, reject) => {
    sftp.stat(target, (error, stats) => {
      if (error) {
        if (error.code === 2) return resolve(null)
        return reject(errorWithCode('sftp-failed', `读取远端路径失败：${target}（${error.message}）`))
      }
      resolve(stats)
    })
  })
}

function sftpReaddir(sftp, target) {
  return new Promise((resolve, reject) => {
    sftp.readdir(target, (error, entries) => {
      if (error) return reject(errorWithCode('sftp-failed', `读取远端目录失败：${target}（${error.message}）`))
      resolve(entries ?? [])
    })
  })
}

function fastPut(sftp, local, remote, deadline) {
  return new Promise((resolve, reject) => {
    const remaining = deadline - Date.now()
    if (remaining <= 0) return reject(timeoutError())
    const timer = setTimeout(() => reject(timeoutError()), remaining)
    sftp.fastPut(local, remote, { concurrency: 16 }, (error) => {
      clearTimeout(timer)
      if (error) reject(errorWithCode('sftp-failed', `上传失败：${local} -> ${remote}（${error.message}）`))
      else resolve()
    })
  })
}

function fastGet(sftp, remote, local, deadline) {
  return new Promise((resolve, reject) => {
    const remaining = deadline - Date.now()
    if (remaining <= 0) return reject(timeoutError())
    const timer = setTimeout(() => reject(timeoutError()), remaining)
    sftp.fastGet(remote, local, { concurrency: 16 }, (error) => {
      clearTimeout(timer)
      if (error) reject(errorWithCode('sftp-failed', `下载失败：${remote} -> ${local}（${error.message}）`))
      else resolve()
    })
  })
}

async function walkLocal(root, { signal } = {}) {
  const entries = []
  async function visit(dir, prefix) {
    if (signal?.aborted) throw errorWithCode('aborted', '传输已取消。')
    const items = await readdir(dir, { withFileTypes: true })
    for (const item of items) {
      const absolute = path.join(dir, item.name)
      const relative = prefix ? `${prefix}/${item.name}` : item.name
      if (item.isDirectory()) {
        entries.push({ absolute, relative, directory: true })
        await visit(absolute, relative)
      } else if (item.isFile()) {
        const stats = await stat(absolute)
        entries.push({ absolute, relative, directory: false, size: stats.size })
      }
    }
  }
  await visit(root, '')
  return entries
}

/** 上传本地文件/目录到远端。 */
export async function upload({ client, localPath, remotePath, timeoutMs = 300000, signal } = {}) {
  const deadline = Date.now() + timeoutMs
  let localStats
  try {
    localStats = await stat(localPath)
  } catch {
    throw errorWithCode('local-not-found', `本地路径不存在：${localPath}`)
  }
  const sftp = await openSftp(client, { signal })
  let bytes = 0
  try {
    if (localStats.isDirectory()) {
      await sftpMkdirp(sftp, remotePath)
      for (const entry of await walkLocal(localPath, { signal })) {
        if (signal?.aborted) throw errorWithCode('aborted', '传输已取消。')
        const target = path.posix.join(remotePath, entry.relative)
        if (entry.directory) await sftpMkdirp(sftp, target)
        else {
          await fastPut(sftp, entry.absolute, target, deadline)
          bytes += entry.size ?? 0
        }
      }
    } else {
      const destination = remotePath.endsWith('/')
        ? path.posix.join(remotePath, path.basename(localPath))
        : remotePath
      await sftpMkdirp(sftp, path.posix.dirname(destination))
      await fastPut(sftp, localPath, destination, deadline)
      bytes = localStats.size
    }
    return { bytes }
  } finally {
    try {
      sftp.end?.()
    } catch {
      // 已关闭。
    }
  }
}

/** 从远端下载文件/目录到本地。 */
export async function download({ client, remotePath, localPath, timeoutMs = 300000, signal } = {}) {
  const deadline = Date.now() + timeoutMs
  const sftp = await openSftp(client, { signal })
  let bytes = 0
  try {
    const rootStats = await sftpStat(sftp, remotePath)
    if (!rootStats) throw errorWithCode('remote-not-found', `远端路径不存在：${remotePath}`)
    if (rootStats.isDirectory()) {
      await mkdir(localPath, { recursive: true })
      const visit = async (remoteDir, localDir) => {
        if (signal?.aborted) throw errorWithCode('aborted', '传输已取消。')
        const entries = await sftpReaddir(sftp, remoteDir)
        for (const entry of entries) {
          if (entry.filename === '.' || entry.filename === '..') continue
          const remoteChild = path.posix.join(remoteDir, entry.filename)
          const localChild = path.join(localDir, entry.filename)
          if (entry.attrs?.isDirectory?.()) {
            await mkdir(localChild, { recursive: true })
            await visit(remoteChild, localChild)
          } else if (entry.attrs?.isFile?.()) {
            await fastGet(sftp, remoteChild, localChild, deadline)
            bytes += Number(entry.attrs.size) || 0
          }
        }
      }
      await visit(remotePath, localPath)
    } else {
      await mkdir(path.dirname(localPath), { recursive: true })
      await fastGet(sftp, remotePath, localPath, deadline)
      bytes = Number(rootStats.size) || 0
    }
    return { bytes }
  } finally {
    try {
      sftp.end?.()
    } catch {
      // 已关闭。
    }
  }
}
