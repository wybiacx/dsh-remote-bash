/**
 * 持久 shell：复用同一条 SSH channel 上的 bash，cd/export 等状态跨调用保留。
 * 采用唯一 marker 包裹命令并读取退出码；无 PTY，因此没有回显和提示符。
 */
import crypto from 'node:crypto'
import { errorWithCode, truncateBytes } from './util.js'

const INIT_PREFIX = '__RB_READY_'

export async function openShell(client, { timeoutMs = 20000 } = {}) {
  const channel = await new Promise((resolve, reject) => {
    let settled = false
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      reject(errorWithCode('shell-open-timeout', '打开持久 shell 超时。'))
    }, timeoutMs)
    try {
      client.shell((error, stream) => {
        if (settled) {
          try {
            stream?.close?.()
          } catch {
            // 已关闭。
          }
          return
        }
        settled = true
        clearTimeout(timer)
        if (error) reject(errorWithCode('shell-open-failed', `打开持久 shell 失败：${error?.message ?? error}`))
        else resolve(stream)
      })
    } catch (error) {
      if (!settled) {
        settled = true
        clearTimeout(timer)
        reject(errorWithCode('shell-open-failed', `打开持久 shell 失败：${error?.message ?? error}`))
      }
    }
  })
  const session = new ShellSession(channel)
  await session.init(timeoutMs)
  return session
}

class ShellSession {
  constructor(channel) {
    this.channel = channel
    this.alive = true
    this.decoder = new TextDecoder('utf-8')
    this.buffer = ''
    this.stderrChunks = []
    this.active = null
    this.chain = Promise.resolve()
    this.closeReason = null
    this.channel.on('data', (chunk) => this.onData(chunk))
    this.channel.stderr?.on('data', (chunk) => {
      if (!this.alive) return
      this.stderrChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))
    })
    this.channel.on('close', () => {
      this.alive = false
      this.failActive(errorWithCode('session-lost', '持久会话连接已断开。'))
    })
    this.channel.on('error', (error) => {
      this.alive = false
      this.failActive(errorWithCode('session-lost', `持久会话出错：${error?.message ?? error}`))
    })
  }

  onData(chunk) {
    if (!this.alive) return
    const text = this.decoder.decode(chunk, { stream: true })
    if (text) this.buffer += text
    if (this.readyCheck) this.readyCheck()
    if (this.active) {
      const maxBuffer = this.active.maxOutputBytes * 2 + 65536
      if (this.buffer.length > maxBuffer) {
        const head = this.buffer.slice(0, this.active.maxOutputBytes + 4096)
        const tail = this.buffer.slice(-this.active.maxOutputBytes)
        this.buffer = `${head}\n…[输出过长，已截断]…\n${tail}`
        this.active.bufferTruncated = true
      }
      this.scan()
    } else if (this.buffer.length > 65536) {
      // 空闲时不该有输出；保留一小段避免无限增长。
      this.buffer = this.buffer.slice(-4096)
    }
  }

  scan() {
    const active = this.active
    if (!active) return
    const beginIndex = this.buffer.indexOf(active.beginMarker)
    if (beginIndex >= 0) {
      const outputStart = beginIndex + active.beginMarker.length
      const endIndex = this.buffer.indexOf(active.endPrefix, outputStart)
      if (endIndex >= 0) {
        const codeStart = endIndex + active.endPrefix.length
        const closeIndex = this.buffer.indexOf('__', codeStart)
        if (closeIndex >= 0) {
          const codeText = this.buffer.slice(codeStart, closeIndex)
          let output = this.buffer.slice(outputStart, endIndex)
          if (output.startsWith('\n')) output = output.slice(1)
          if (output.endsWith('\n')) output = output.slice(0, -1)
          this.buffer = this.buffer.slice(closeIndex + 2)
          this.completeActive({
            code: Number.parseInt(codeText, 10),
            output,
          })
          return
        }
      }
    }
  }

  completeActive(result) {
    const active = this.active
    if (!active) return
    this.active = null
    clearTimeout(active.timer)
    const stderr = Buffer.concat(this.stderrChunks)
    this.stderrChunks = []
    let output = result.output ?? ''
    if (stderr.length > 0) {
      const text = stderr.toString('utf8').replace(/^\uFFFD+/, '').replace(/\uFFFD+$/, '')
      if (text) output += `${output && !output.endsWith('\n') ? '\n' : ''}[stderr]\n${text}`
    }
    const capped = truncateBytes(Buffer.from(output, 'utf8'), active.maxOutputBytes)
    active.resolve({
      code: Number.isFinite(result.code) ? result.code : null,
      output: capped.buffer.toString('utf8'),
      truncated: active.bufferTruncated || capped.truncated,
      timedOut: false,
    })
  }

  failActive(error) {
    const active = this.active
    if (!active) return
    this.active = null
    clearTimeout(active.timer)
    active.reject(error)
  }

  waitForReady(marker, timeoutMs) {
    return new Promise((resolve, reject) => {
      let settled = false
      const timer = setTimeout(() => {
        if (settled) return
        settled = true
        reject(errorWithCode('shell-open-timeout', '持久 shell 初始化超时。'))
      }, timeoutMs)
      const check = () => {
        if (settled) return
        const index = this.buffer.indexOf(marker)
        if (index < 0) return
        settled = true
        clearTimeout(timer)
        this.buffer = this.buffer.slice(index + marker.length)
        resolve()
      }
      this.readyCheck = check
      check()
    })
  }

  async init(timeoutMs) {
    const marker = `${INIT_PREFIX}${crypto.randomBytes(8).toString('hex')}__`
    // 重定向只作用于探测命令：exec 后的 bash 必须继承正常的 stderr，否则会话命令的 stderr 会被丢进 /dev/null。
    this.channel.write(`command -v bash >/dev/null 2>&1 && exec bash --noprofile --norc -s || exec sh -s\n`)
    this.channel.write(`printf '${marker}\\n'\n`)
    await this.waitForReady(marker, timeoutMs)
    this.readyCheck = null
    this.buffer = ''
    this.stderrChunks = []
  }

  async run(command, { timeoutMs = 60000, maxOutputBytes = 32768 } = {}) {
    if (!this.alive) throw errorWithCode('session-lost', '持久会话已关闭，请重新执行（会自动重连）。')
    const task = () => this.runOnce(command, { timeoutMs, maxOutputBytes })
    const run = this.chain.then(task)
    this.chain = run.catch(() => {})
    return run
  }

  runOnce(command, { timeoutMs, maxOutputBytes }) {
    return new Promise((resolve, reject) => {
      const token = crypto.randomBytes(8).toString('hex')
      this.active = {
        token,
        beginMarker: `__RB_B_${token}__`,
        endPrefix: `__RB_E_${token}:`,
        maxOutputBytes,
        bufferTruncated: false,
        resolve,
        reject,
        timer: setTimeout(() => {
          const active = this.active
          if (!active) return
          this.active = null
          active.resolve({
            code: null,
            output: '',
            truncated: true,
            timedOut: true,
          })
          // 无 PTY 时无法可靠中断远端命令，直接关闭会话避免错位。
          void this.close()
        }, timeoutMs),
      }
      this.buffer = ''
      this.stderrChunks = []
      const frame = [
        `printf '\\n${this.active.beginMarker}\\n'`,
        command,
        `printf '\\n${this.active.endPrefix}%s__\\n' "$?"`,
        '',
      ].join('\n')
      try {
        this.channel.write(frame)
      } catch (error) {
        this.failActive(errorWithCode('session-lost', `写入持久会话失败：${error?.message ?? error}`))
      }
    })
  }

  async close() {
    if (!this.alive) return
    this.alive = false
    this.failActive(errorWithCode('session-closed', '持久会话已关闭。'))
    try {
      this.channel.write('exit\n')
    } catch {
      // 忽略。
    }
    try {
      this.channel.end()
    } catch {
      // 忽略。
    }
    setTimeout(() => {
      try {
        this.channel.destroy?.()
      } catch {
        // 忽略。
      }
    }, 200).unref?.()
  }
}
