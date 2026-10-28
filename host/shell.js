/** 无 PTY 持久 shell；控制帧一次提交，业务 stdin 与 shell 源码隔离。 */
import crypto from 'node:crypto'
import { createByteCollector, errorWithCode, quoteShell, safeUtf8, truncateBytes } from './util.js'
import { createSudoResponder } from './ssh.js'

export async function openShell(client, { timeoutMs = 20000, signal } = {}) {
  const deadline = Date.now() + timeoutMs
  const channel = await new Promise((resolve, reject) => {
    let settled = false
    const finish = (error, stream) => {
      if (settled) { stream?.destroy?.(); return }
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
      if (error) reject(error)
      else resolve(stream)
    }
    const onAbort = () => finish(errorWithCode('aborted', '打开持久 shell 已取消。'))
    const timer = setTimeout(() => finish(errorWithCode('shell-open-timeout', '打开持久 shell 超时。')), timeoutMs)
    if (signal?.aborted) { onAbort(); return }
    signal?.addEventListener('abort', onAbort, { once: true })
    try {
      client.shell(false, (error, stream) => finish(error ? errorWithCode('shell-open-failed', `打开持久 shell 失败：${error.message}`) : null, stream))
    } catch (error) { finish(error) }
  })
  const session = new ShellSession(channel)
  try {
    channel.write('command -v bash >/dev/null 2>&1 && exec bash --noprofile --norc -s || exec sh -s\n')
    const result = await session.run('true', { timeoutMs: Math.max(1, deadline - Date.now()), signal })
    if (result.aborted) throw errorWithCode('aborted', '初始化持久 shell 已取消。')
    if (result.timedOut) throw errorWithCode('shell-open-timeout', '持久 shell 初始化超时。')
    return session
  } catch (error) { await session.close(); throw error }
}

/** 每条流单独识别随机帧；跨包残留仅保留一个 marker 长度，正文直接进入有界 collector。 */
class FrameReader {
  constructor(token, collector, complete, fail) {
    this.begin = Buffer.from(`\x1eRB_B_${token}\x1f`)
    this.end = Buffer.from(`\x1eRB_E_${token}:`)
    this.pending = Buffer.alloc(0)
    this.begun = false
    this.ended = false
    this.collector = collector
    this.complete = complete
    this.fail = fail
  }
  push(chunk) {
    if (this.ended) return
    this.pending = Buffer.concat([this.pending, Buffer.from(chunk)])
    if (!this.begun) {
      const start = this.pending.indexOf(this.begin)
      if (start === -1) { this.pending = Buffer.from(this.pending.subarray(-(this.begin.length - 1))); return }
      this.begun = true
      this.pending = this.pending.subarray(start + this.begin.length)
    }
    const end = this.pending.indexOf(this.end)
    if (end === -1) {
      const flush = Math.max(0, this.pending.length - this.end.length + 1)
      if (flush) this.collector.push(Buffer.from(this.pending.subarray(0, flush)))
      this.pending = Buffer.from(this.pending.subarray(flush))
      return
    }
    if (end) this.collector.push(Buffer.from(this.pending.subarray(0, end)))
    this.pending = this.pending.subarray(end)
    const close = this.pending.indexOf(0x1f, this.end.length)
    if (close === -1 && this.pending.length <= this.end.length + 4) return
    const codeText = close === -1 ? '' : this.pending.subarray(this.end.length, close).toString()
    if (!/^\d{1,3}$/.test(codeText) || Number(codeText) > 255) {
      this.fail(errorWithCode('shell-protocol', '持久 shell 返回无效控制帧。'))
      return
    }
    this.ended = true
    this.pending = Buffer.alloc(0)
    this.complete(Number(codeText))
  }
}

class ShellSession {
  constructor(channel) {
    this.channel = channel
    this.alive = true
    this.active = null
    this.chain = Promise.resolve()
    channel.on('data', (chunk) => this.active?.stdoutReader.push(chunk))
    channel.stderr?.on('data', (chunk) => this.active?.sudoResponder.push(chunk))
    channel.on('close', () => this.fail(errorWithCode('session-lost', '持久会话连接已断开。')))
    channel.on('error', () => this.fail(errorWithCode('session-lost', '持久会话连接出错。')))
  }

  fail(error) {
    this.alive = false
    const active = this.active
    if (active) { this.active = null; active.cleanup(); active.reject(error) }
    try { this.channel.destroy?.() } catch { /* already closed */ }
  }

  run(command, { timeoutMs = 60000, maxOutputBytes = 32768, signal, sudoInput, validate } = {}) {
    if (!this.alive) return Promise.reject(errorWithCode('session-lost', '持久会话已关闭，请重新执行（会自动重连）。'))
    if (signal?.aborted) return Promise.reject(errorWithCode('aborted', '执行已取消。'))
    // 排队取消立即返回，但不关闭别的调用正在使用的通道；轮到它时不再执行。
    let started = false
    let onQueuedAbort
    const cancelled = new Promise((_, reject) => {
      onQueuedAbort = () => { if (!started) reject(errorWithCode('aborted', '排队执行已取消。')) }
      signal?.addEventListener('abort', onQueuedAbort, { once: true })
    })
    const task = this.chain.then(async () => {
      if (signal?.aborted) throw errorWithCode('aborted', '排队执行已取消。')
      if (!this.alive) throw errorWithCode('session-lost', '持久会话已关闭。')
      await validate?.()
      if (signal?.aborted) throw errorWithCode('aborted', '执行已取消。')
      if (!this.alive) throw errorWithCode('session-lost', '持久会话已关闭。')
      signal?.removeEventListener('abort', onQueuedAbort)
      started = true
      return this.runOnce(command, { timeoutMs, maxOutputBytes, signal, sudoInput })
    })
    this.chain = task.catch(() => {})
    return Promise.race([task, cancelled]).finally(() => signal?.removeEventListener('abort', onQueuedAbort))
  }

  runOnce(command, { timeoutMs, maxOutputBytes, signal, sudoInput }) {
    return new Promise((resolve, reject) => {
      const token = crypto.randomBytes(24).toString('hex')
      const stdout = createByteCollector(maxOutputBytes)
      const stderr = createByteCollector(maxOutputBytes)
      let outCode = null
      let errCode = null
      const finish = ({ timedOut = false, aborted = false } = {}) => {
        if (this.active !== active) return
        this.active = null
        active.cleanup()
        const out = stdout.finish()
        const err = stderr.finish()
        const parts = [out.buffer]
        if (err.buffer.length) parts.push(Buffer.from('\n[stderr]\n'), err.buffer)
        const capped = truncateBytes(Buffer.concat(parts), maxOutputBytes)
        resolve({ code: timedOut || aborted ? null : outCode, output: safeUtf8(capped.buffer), truncated: out.truncated || err.truncated || capped.truncated, timedOut, aborted })
        if (timedOut || aborted) void this.close()
      }
      const check = () => {
        if (outCode === null || errCode === null) return
        if (outCode !== errCode) { this.fail(errorWithCode('shell-protocol', '持久 shell 退出码不一致。')); return }
        finish()
      }
      const onAbort = () => finish({ aborted: true })
      const timer = setTimeout(() => finish({ timedOut: true }), timeoutMs)
      const active = {
        resolve, reject,
        cleanup: () => { clearTimeout(timer); signal?.removeEventListener('abort', onAbort) },
        stdoutReader: new FrameReader(token, stdout, (code) => { outCode = code; check() }, (error) => this.fail(error)),
        stderrReader: new FrameReader(token, stderr, (code) => { errCode = code; check() }, (error) => this.fail(error)),
      }
      active.sudoResponder = createSudoResponder(sudoInput, (text) => this.channel.write(text), (chunk) => active.stderrReader.push(chunk), (error) => this.fail(error))
      this.active = active
      signal?.addEventListener('abort', onAbort, { once: true })
      if (signal?.aborted) { onAbort(); return }
      const codeVar = `__rb_code_${token}`
      // 整个复合语句先被 shell 解析完，sudo 才能开始读取随后的密码输入。
      // 普通 eval 在当前 shell 中运行，保留 cd/export；其 stdin 为 /dev/null。
      const frame = [
        '{',
        `printf '\\036RB_B_${token}\\037'`,
        `printf '\\036RB_B_${token}\\037' >&2`,
        `if eval ${quoteShell(command)}${sudoInput ? '' : ' </dev/null'}; then ${codeVar}=0; else ${codeVar}=$?; fi`,
        `printf '\\036RB_E_${token}:%s\\037' "$${codeVar}"`,
        `printf '\\036RB_E_${token}:%s\\037' "$${codeVar}" >&2`,
        `unset ${codeVar}`,
        '}', '',
      ].join('\n')
      try { this.channel.write(frame) } catch { this.fail(errorWithCode('session-lost', '写入持久会话失败。')) }
    })
  }

  async close() {
    if (!this.alive) return
    this.fail(errorWithCode('session-closed', '持久会话已关闭。'))
  }
}
