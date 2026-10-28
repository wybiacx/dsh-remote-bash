/**
 * 模型侧工具：remote_bash / remote_hosts / remote_upload / remote_download / remote_sessions。
 * 与设置页共用 service.js 的同一套能力；审批在工具层完成。
 */
import { assessCommand } from './danger.js'
import { errorWithCode } from './util.js'

const MAX_RENDER_CHARS = 48000

function shorten(text, max = 160) {
  const value = String(text ?? '')
  return value.length > max ? `${value.slice(0, max)}…` : value
}

function truncateText(text, max) {
  const value = String(text ?? '')
  if (value.length <= max) return value
  return `${value.slice(0, Math.floor(max * 0.7))}\n…[输出过长，已截断]…\n${value.slice(-Math.floor(max * 0.3))}`
}

function duration(ms) {
  const value = Number(ms)
  if (!Number.isFinite(value) || value < 0) return '—'
  if (value < 1000) return `${Math.round(value)}ms`
  return `${(value / 1000).toFixed(1)}s`
}

function humanBytes(bytes) {
  const value = Number(bytes)
  if (!Number.isFinite(value) || value <= 0) return '0B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let index = 0
  let current = value
  while (current >= 1024 && index < units.length - 1) {
    current /= 1024
    index += 1
  }
  return `${current >= 10 || index === 0 ? Math.round(current) : current.toFixed(1)}${units[index]}`
}

function hostOutcome(host) {
  if (host.status === 'timeout') return `超时${host.error?.message ? `：${host.error.message}` : ''}`
  if (host.error) return `失败：${host.error.message}${host.error.code ? `（${host.error.code}）` : ''}`
  if (host.exitCode !== null && host.exitCode !== undefined && host.exitCode !== 0) return `退出码 ${host.exitCode}`
  return ''
}

/**
 * 命令结果正文保持精简：成功时只有输出；失败/超时/多主机才加一行轻量标头。
 * 命令、说明、执行方式已经在工具调用卡片里，不再重复。
 */
function renderRun(value) {
  const hosts = Array.isArray(value?.hosts) ? value.hosts : []
  const multi = hosts.length > 1
  const okCount = hosts.filter((host) => host.status === 'ok').length
  const blocks = []
  for (const host of hosts) {
    const lines = []
    const outcome = hostOutcome(host)
    if (multi) lines.push(outcome ? `${host.name} · ${outcome}` : host.name)
    else if (outcome) lines.push(outcome)
    if (host.hostKeyStatus === 'new' && host.fingerprint) lines.push(`首次连接，已记录主机指纹 ${host.fingerprint}`)
    const output = typeof host.output === 'string' ? host.output.replace(/^\n+/, '').replace(/\n$/, '') : ''
    if (output) lines.push(output)
    if (host.truncated) lines.push('（输出已截断）')
    blocks.push(lines.join('\n') || '（无输出）')
  }
  let text = blocks.join('\n\n')
  text = truncateText(text, MAX_RENDER_CHARS)
  if (!multi) return text
  return `${okCount}/${hosts.length} 台成功 · ${duration(value?.durationMs)}\n\n${text}`
}

function renderHosts(value) {
  const hosts = Array.isArray(value?.hosts) ? value.hosts : []
  if (hosts.length === 0) {
    return '还没有配置主机。请让用户在 DSH 设置 → Remote Bash 中添加主机与密码。'
  }
  const lines = [`已配置 ${hosts.length} 台远程主机：`]
  for (const host of hosts) {
    const parts = [`- ${host.name}（${host.username}@${host.host}:${host.port}）`]
    parts.push(host.auth === 'key' ? '私钥' : '密码')
    if (host.tags?.length) parts.push(host.tags.join('/'))
    const secret = host.secret ?? {}
    if (secret.available === false) parts.push('⚠ 凭据服务不可用')
    else if (host.auth === 'key') {
      if (!(secret.fields?.privateKey || host.keyPath)) parts.push('⚠ 私钥未配置')
    } else if (!secret.fields?.password) parts.push('⚠ 密码未配置')
    lines.push(parts.join(' · '))
  }
  const groups = Array.isArray(value?.groups) ? value.groups : []
  if (groups.length > 0) lines.push(`分组：${groups.map((group) => `${group.tag}（${group.hostIds.length}）`).join('、')}`)
  return lines.join('\n')
}

function renderTransfer(value) {
  const hosts = Array.isArray(value?.hosts) ? value.hosts : []
  const multi = hosts.length > 1
  const action = value?.action === 'upload' ? '上传' : '下载'
  const okCount = hosts.filter((host) => host.status === 'ok').length
  const lines = hosts.map((host) => {
    const meta = []
    if (multi) meta.push(host.name)
    if (host.status === 'ok') meta.push(`${action}成功 · ${humanBytes(host.bytes)}`)
    else meta.push(`${action}失败：${host.error?.message ?? '未知错误'}${host.error?.code ? `（${host.error.code}）` : ''}`)
    return meta.join(' · ')
  })
  if (!multi) return lines.join('\n')
  return `${okCount}/${hosts.length} 台成功\n${lines.join('\n')}`
}

function renderSessions(value) {
  const sessions = Array.isArray(value?.sessions) ? value.sessions : []
  const lines = []
  if (value?.action === 'close') {
    lines.push(`已关闭 ${value.closed ?? 0} 个持久会话。`)
    if (sessions.length > 0) lines.push(`当前仍有 ${sessions.length} 个：`)
    else return lines.join('\n')
  } else {
    if (sessions.length === 0) return '当前没有持久会话。'
    lines.push(`当前有 ${sessions.length} 个持久会话：`)
  }
  for (const session of sessions) {
    lines.push(`- ${session.label} @ ${session.hostName ?? session.hostId} · 最近使用 ${duration(Date.now() - (session.lastUsedAt ?? Date.now()))}前`)
  }
  return lines.join('\n')
}

const RUN_PARAMETERS = {
  type: 'object',
  properties: {
    targets: {
      type: 'string',
      description: '目标主机：主机名或 id 用逗号分隔；@分组名 表示整组；all 表示全部已配置主机。',
    },
    command: { type: 'string', description: '在远程主机上执行的 shell 命令（目标为 Linux/macOS）。' },
    description: {
      type: 'string',
      description: '一句话说明这条命令要做什么（中文，例如「查看磁盘占用」）。会显示在审批弹窗和会话卡片里，方便用户确认；每次执行命令都应填写。',
    },
    cwd: { type: 'string', description: '可选：执行前 cd 到的工作目录（绝对路径）。' },
    timeoutSec: { type: 'number', description: '单机命令超时秒数，默认 60，最大 3600。' },
    session: {
      type: 'string',
      description: '可选：持久会话名（字母/数字/._-，≤32 字符）。相同名字跨调用复用同一个 shell，cd/export 状态保留。',
    },
    sudo: { type: 'boolean', description: '省略时使用主机默认设置；false 禁用提权。需要认证时使用已保存的 sudo 密码，其次登录密码。' },
    maxOutputBytes: { type: 'integer', description: '单机输出上限（字节），默认 32768，最大 1048576。' },
  },
  required: ['targets', 'command'],
  additionalProperties: false,
}

const RUN_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    command: { type: 'string' },
    description: { type: 'string' },
    cwd: {},
    session: {},
    sudo: { type: 'boolean' },
    startedAt: { type: 'number' },
    durationMs: { type: 'number' },
    hosts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          hostId: { type: 'string' },
          name: { type: 'string' },
          host: { type: 'string' },
          port: { type: 'number' },
          username: { type: 'string' },
          status: { type: 'string', enum: ['ok', 'error', 'timeout'] },
          exitCode: {},
          signal: {},
          output: { type: 'string' },
          truncated: { type: 'boolean' },
          durationMs: { type: 'number' },
          error: { type: 'object', additionalProperties: true },
          fingerprint: {},
          keyType: {},
          hostKeyStatus: {},
        },
        additionalProperties: true,
      },
    },
  },
  additionalProperties: true,
}

const TRANSFER_PARAMETERS = {
  type: 'object',
  properties: {
    targets: { type: 'string', description: '目标主机：主机名/id 逗号分隔、@分组名、或 all。' },
    localPath: { type: 'string', description: '本地文件或目录路径（建议绝对路径；支持 ~ 与 {host}/{name}/{id} 模板）。' },
    remotePath: { type: 'string', description: '远端文件或目录路径（支持 ~ 与 {host}/{name}/{id}/{basename} 模板）。' },
    timeoutSec: { type: 'number', description: '单机传输超时秒数，默认至少 60。' },
  },
  required: ['targets', 'localPath', 'remotePath'],
  additionalProperties: false,
}

const TRANSFER_OUTPUT_SCHEMA = {
  type: 'object',
  properties: {
    action: { type: 'string', enum: ['upload', 'download'] },
    localPath: { type: 'string' },
    remotePath: { type: 'string' },
    durationMs: { type: 'number' },
    hosts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          hostId: { type: 'string' },
          name: { type: 'string' },
          status: { type: 'string', enum: ['ok', 'error'] },
          bytes: { type: 'number' },
          durationMs: { type: 'number' },
          localPath: { type: 'string' },
          remotePath: { type: 'string' },
          error: { type: 'object', additionalProperties: true },
        },
        additionalProperties: true,
      },
    },
  },
  additionalProperties: true,
}

function textOutput(summary) {
  return [{ type: 'text', text: summary }]
}

export function installTools(ctx, { service, gate, config }) {
  const tools = []

  tools.push({
    name: 'remote_bash',
    description:
      '在已配置的一台或多台远程 Linux/macOS 主机上执行 shell 命令（SSH）。' +
      'targets 支持 主机名/id 逗号分隔、@分组名、all；一次调用会并行执行同一命令并汇总每台主机的退出码与输出。' +
      '需要保留 cd/export 等 shell 状态时传 session；需要 root 权限时传 sudo。' +
      '危险命令（rm -rf、mkfs、dd 写设备、关机、停关键服务、改账户、清防火墙、sudo 等）会先请求用户审批。' +
      '每次调用都要用 description 写一句中文说明命令目的（会显示在审批弹窗与会话卡片里，帮助用户确认）。' +
      '先不确定有哪些主机时用 remote_hosts 查看。',
    parameters: RUN_PARAMETERS,
    output: {
      schema: RUN_OUTPUT_SCHEMA,
      render: (_args, value) => textOutput(renderRun(value)),
    },
    presentCall: (args) => ({
      card: 'terminal',
      title: `远程执行 · ${shorten(args?.targets ?? '', 60) || '主机'}`,
      description: shorten(args?.description || args?.command || '', 160),
    }),
    timeoutMs: 600000,
    async execute(args, exec) {
      const targets = String(args?.targets ?? '').trim()
      const command = String(args?.command ?? '')
      const description = typeof args?.description === 'string' ? args.description.trim().slice(0, 200) : ''
      if (!command.trim()) throw errorWithCode('invalid-command', 'command 不能为空。')
      if (!targets) throw errorWithCode('unknown-target', 'targets 不能为空（主机名、@分组 或 all）。')
      const plan = await service.prepareRun({ ...args, targets, command })
      const hosts = plan.hosts
      const assessment = assessCommand(command, { extraPatterns: config.extraDangerousPatterns })
      const matches = [...assessment.matches]
      const sudoRequested = hosts.some((host) => host.useSudo)
      if (sudoRequested && !matches.some((match) => match.id === 'sudo' || match.id === 'sudo-mode')) {
        matches.push({ id: 'sudo-mode', label: 'sudo 提权' })
      }
      // 不在这里按 matches 短路：approvalMode='always' 时 gate 需要看到每条命令；
      // 'dangerous' 模式下无命中的命令由 gate 返回 not-needed，不会打扰用户。
      const verdict = await gate.check({
        agent: exec?.agent,
        toolName: 'remote_bash',
        callId: exec?.callId,
        signal: exec?.signal,
        command,
        description,
        hostNames: hosts.map((host) => host.name),
        matches,
      })
      if (!verdict.allowed) throw errorWithCode('approval-denied', verdict.reason ?? '命令未获批准。')
      const result = await service.run({
        plan,
        agentId: exec?.agent?.id,
        signal: exec?.signal,
      })
      return { ...result, description }
    },
  })

  tools.push({
    name: 'remote_hosts',
    description:
      '列出已配置的远程 Linux/macOS 主机：名称、id、用户名@地址:端口、认证方式、分组标签、凭据是否已配置。' +
      '在不确定有哪些主机、或需要选择 target（主机名/id/@分组/all）时先用它。不会返回密码等机密。',
    parameters: { type: 'object', properties: {}, additionalProperties: false },
    output: {
      schema: {
        type: 'object',
        properties: {
          dataDir: { type: 'string' },
          approvalMode: { type: 'string' },
          credentialsAvailable: { type: 'boolean' },
          hosts: { type: 'array', items: { type: 'object', additionalProperties: true } },
          groups: { type: 'array', items: { type: 'object', additionalProperties: true } },
        },
        additionalProperties: true,
      },
      render: (_args, value) => textOutput(renderHosts(value)),
    },
    presentCall: () => ({ card: 'generic', title: '远程主机列表', kind: 'read' }),
    timeoutMs: 60000,
    isConcurrencySafe: () => true,
    async execute() {
      const state = await service.state()
      return {
        dataDir: state.settings.dataDir,
        approvalMode: state.settings.approvalMode,
        credentialsAvailable: state.credentialsAvailable,
        hosts: state.hosts.map((host) => ({
          id: host.id,
          name: host.name,
          host: host.host,
          port: host.port,
          username: host.username,
          auth: host.auth,
          keyPath: host.keyPath,
          tags: host.tags,
          note: host.note,
          sudo: host.sudo,
          secret: host.secret,
        })),
        groups: state.groups,
      }
    },
  })

  tools.push({
    name: 'remote_upload',
    description:
      '通过 SFTP 把本地文件或目录上传到一台或多台远程主机（目录递归上传）。' +
      'localPath 建议用绝对路径；remotePath 支持 ~ 与 {host}/{name}/{id} 模板，多主机时用模板可避免互相覆盖。',
    parameters: TRANSFER_PARAMETERS,
    output: {
      schema: TRANSFER_OUTPUT_SCHEMA,
      render: (_args, value) => textOutput(renderTransfer(value)),
    },
    presentCall: (args) => ({
      card: 'generic',
      title: `远程上传 · ${shorten(args?.targets ?? '', 60) || '主机'}`,
      kind: 'other',
      rawInput: { localPath: args?.localPath, remotePath: args?.remotePath },
    }),
    timeoutMs: 1800000,
    async execute(args, exec) {
      if (!String(args?.localPath ?? '').trim()) throw errorWithCode('invalid-path', 'localPath 不能为空。')
      if (!String(args?.remotePath ?? '').trim()) throw errorWithCode('invalid-path', 'remotePath 不能为空。')
      return service.upload({
        targets: args?.targets,
        localPath: args?.localPath,
        remotePath: args?.remotePath,
        timeoutSec: args?.timeoutSec,
        signal: exec?.signal,
      })
    },
  })

  tools.push({
    name: 'remote_download',
    description:
      '通过 SFTP 从一台或多台远程主机下载文件或目录（目录递归下载）。' +
      '多主机下载时 localPath 作为目录：文件保存为 <name>-<basename>，目录保存到 <name>/ 子目录；' +
      'localPath 支持 {host}/{name}/{id}/{basename} 模板，remotePath 支持 ~ 与同名模板。',
    parameters: TRANSFER_PARAMETERS,
    output: {
      schema: TRANSFER_OUTPUT_SCHEMA,
      render: (_args, value) => textOutput(renderTransfer(value)),
    },
    presentCall: (args) => ({
      card: 'generic',
      title: `远程下载 · ${shorten(args?.targets ?? '', 60) || '主机'}`,
      kind: 'other',
      rawInput: { remotePath: args?.remotePath, localPath: args?.localPath },
    }),
    timeoutMs: 1800000,
    async execute(args, exec) {
      if (!String(args?.localPath ?? '').trim()) throw errorWithCode('invalid-path', 'localPath 不能为空。')
      if (!String(args?.remotePath ?? '').trim()) throw errorWithCode('invalid-path', 'remotePath 不能为空。')
      return service.download({
        targets: args?.targets,
        remotePath: args?.remotePath,
        localPath: args?.localPath,
        timeoutSec: args?.timeoutSec,
        signal: exec?.signal,
      })
    },
  })

  tools.push({
    name: 'remote_sessions',
    description:
      '管理 remote_bash 的持久会话：action=list 列出当前会话（label、主机、最近使用时间），action=close 关闭会话（传 session 关闭同名会话，不传则关闭本会话 Agent 的全部持久会话）。',
    parameters: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['list', 'close'], description: 'list 或 close。' },
        session: { type: 'string', description: 'close 时可指定要关闭的会话名；省略则关闭当前 Agent 的全部会话。' },
      },
      required: ['action'],
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          action: { type: 'string' },
          closed: { type: 'number' },
          sessions: { type: 'array', items: { type: 'object', additionalProperties: true } },
        },
        additionalProperties: true,
      },
      render: (_args, value) => textOutput(renderSessions(value)),
    },
    presentCall: (args) => ({ card: 'generic', title: args?.action === 'close' ? '关闭远程会话' : '远程会话列表', kind: 'read' }),
    timeoutMs: 60000,
    async execute(args, exec) {
      const agentId = exec?.agent?.id
      const action = args?.action === 'close' ? 'close' : 'list'
      let sessions = service.listSessions({ agentId })
      if (action === 'list') return { action, sessions }
      const label = typeof args?.session === 'string' && args.session.trim() ? args.session.trim() : undefined
      const targetsToClose = label ? sessions.filter((session) => session.label === label) : sessions
      let closed = 0
      for (const session of targetsToClose) {
        if (await service.closeSession({ key: session.key })) closed += 1
      }
      sessions = service.listSessions({ agentId })
      return { action, closed, sessions }
    },
  })

  return ctx.effect(
    () => {
      const disposers = tools.map((tool) => ctx.tools.register(tool))
      return () => {
        for (const dispose of disposers) {
          try {
            dispose()
          } catch {
            // 已释放。
          }
        }
      }
    },
    'remote-bash.tools',
  )
}
