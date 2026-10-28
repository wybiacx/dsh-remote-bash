/**
 * 基础工具：原子写、JSON 读写、shell 引号、输出截断、并发限制、错误构造。
 * 不依赖 DSH 服务，可被测试直接 import。
 */
import { mkdir, readFile, rename, writeFile, chmod } from 'node:fs/promises'
import crypto from 'node:crypto'
import path from 'node:path'

/** 当前 epoch 毫秒。 */
export function nowMs() {
  return Date.now()
}

/** 建目录（默认 0700）。 */
export async function ensureDir(dir, mode = 0o700) {
  await mkdir(dir, { recursive: true, mode })
}

/** 同目录临时文件 + rename 的原子写；默认 0600。 */
export async function writeFileAtomic(file, text, { mode = 0o600 } = {}) {
  const dir = path.dirname(file)
  await ensureDir(dir)
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`)
  await writeFile(tmp, text, { mode })
  try {
    await chmod(tmp, mode)
  } catch {
    // 某些文件系统（如 exFAT）不支持 chmod，忽略。
  }
  await rename(tmp, file)
}

/** 读 JSON；文件不存在返回 fallback，内容损坏抛 code='corrupt-data'（不静默丢数据）。 */
export async function readJsonFile(file, fallback) {
  let raw
  try {
    raw = await readFile(file, 'utf8')
  } catch (error) {
    if (error?.code === 'ENOENT') return typeof fallback === 'function' ? fallback() : fallback
    throw error
  }
  try {
    return JSON.parse(raw)
  } catch (error) {
    const wrapped = new Error(`数据文件损坏，无法解析：${file}`)
    wrapped.code = 'corrupt-data'
    wrapped.cause = error
    throw wrapped
  }
}

/** 原子写 JSON（0600，带缩进与换行）。 */
export async function writeJsonFile(file, value, opts = {}) {
  await writeFileAtomic(file, `${JSON.stringify(value, null, 2)}\n`, opts)
}

/** POSIX shell 单引号转义：' -> '\'' */
export function quoteShell(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`
}

/** Buffer -> string，去掉边界处可能被切断的 UTF-8 替换字符。 */
export function safeUtf8(buffer) {
  return Buffer.from(buffer).toString('utf8').replace(/^\uFFFD+/, '').replace(/\uFFFD+$/, '')
}

const TRUNCATE_NOTICE = '\n…[输出过长，已截断]…\n'

/** 按字节头尾截断，中间放提示。 */
export function truncateBytes(buffer, maxBytes) {
  const input = Buffer.from(buffer)
  if (input.length <= maxBytes) return { buffer: input, truncated: false }
  const notice = Buffer.from(TRUNCATE_NOTICE, 'utf8')
  const budget = Math.max(0, maxBytes - notice.length)
  const headBudget = Math.floor(budget * 0.6)
  const tailBudget = budget - headBudget
  const head = input.subarray(0, headBudget)
  const tail = tailBudget > 0 ? input.subarray(input.length - tailBudget) : Buffer.alloc(0)
  return { buffer: Buffer.concat([head, notice, tail]), truncated: true }
}

/**
 * 流式输出收集器：最多保留 maxBytes 头部与 maxBytes/2 尾部，避免大输出吃内存。
 */
class ByteCollector {
  constructor(maxBytes) {
    this.maxBytes = Math.max(1024, maxBytes)
    this.head = []
    this.headLength = 0
    this.tail = []
    this.tailLength = 0
    this.total = 0
    this.truncated = false
  }

  push(chunk) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    if (buffer.length === 0) return
    this.total += buffer.length
    let rest = buffer
    if (this.headLength < this.maxBytes) {
      const take = Math.min(rest.length, this.maxBytes - this.headLength)
      this.head.push(rest.subarray(0, take))
      this.headLength += take
      rest = rest.subarray(take)
    }
    if (rest.length === 0) return
    this.truncated = true
    this.tail.push(rest)
    this.tailLength += rest.length
    const tailCap = Math.floor(this.maxBytes / 2)
    while (this.tailLength > tailCap && this.tail.length > 1) {
      const dropped = this.tail.shift()
      this.tailLength -= dropped.length
    }
    if (this.tailLength > tailCap && this.tail.length === 1) {
      const only = this.tail[0]
      const keep = only.subarray(only.length - tailCap)
      this.tail = [keep]
      this.tailLength = keep.length
    }
  }

  finish() {
    const headBuffer = Buffer.concat(this.head)
    if (!this.truncated) return { buffer: headBuffer, truncated: false }
    return truncateBytes(Buffer.concat([headBuffer, ...this.tail]), this.maxBytes)
  }
}

/** 创建流式输出收集器。 */
export function createByteCollector(maxBytes) {
  return new ByteCollector(maxBytes)
}

/** 逐项并发执行（上限 limit），返回与输入同序的结果信封 { ok, value|error }。 */
export async function mapLimit(items, limit, worker) {
  const list = Array.from(items)
  const results = new Array(list.length)
  let cursor = 0
  const width = Math.max(1, Math.min(Math.floor(limit) || 1, list.length || 1))
  const run = async () => {
    while (true) {
      const index = cursor++
      if (index >= list.length) return
      try {
        results[index] = { ok: true, value: await worker(list[index], index) }
      } catch (error) {
        results[index] = { ok: false, error }
      }
    }
  }
  await Promise.all(Array.from({ length: width }, run))
  return results
}

/** 生成主机 id 用 slug。 */
export function slugify(input) {
  const base = String(input ?? '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
  const slug = base
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48)
  return slug || 'host'
}

/** 字符串数组归一：去空、去重、截断。 */
export function uniqueStrings(list, { max = 16, maxLength = 64 } = {}) {
  const seen = new Set()
  const result = []
  for (const item of Array.isArray(list) ? list : []) {
    if (typeof item !== 'string') continue
    const value = item.trim().slice(0, maxLength)
    if (!value) continue
    const key = value.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    result.push(value)
    if (result.length >= max) break
  }
  return result
}

/** 整数收敛到 [min, max]。 */
export function clampInt(value, min, max, fallback) {
  const number = Number(value)
  if (!Number.isFinite(number)) return fallback
  return Math.min(max, Math.max(min, Math.round(number)))
}

/** 构造带 code/details 的 Error。 */
export function errorWithCode(code, message, details) {
  const error = new Error(message)
  error.code = code
  if (details !== undefined) error.details = details
  return error
}

/** sleep。 */
export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/** 普通对象判断。 */
export function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}
