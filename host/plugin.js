/**
 * Remote Bash · Host 插件装配。
 *
 * 1. 解析数据目录与插件配置；
 * 2. 组装清单 / 指纹 / 凭据 / SSH / 持久会话的核心 service；
 * 3. 注册 5 个 Agent 工具、浏览器 RPC（设置页面通道）、一段系统提示词。
 */
import { createInventory } from './inventory.js'
import { createKnownHosts } from './knownhosts.js'
import { createSecretStore } from './credentials.js'
import { createService } from './service.js'
import { createApprovalGate } from './approval.js'
import { installTools } from './tools.js'
import { installRpc } from './rpc.js'
import { installPrompt } from './prompt.js'
import { createPaths, resolveDataDir } from './paths.js'
import { clampInt, isPlainObject } from './util.js'

export const name = 'remote-bash'
export const inject = ['tools']

const APPROVAL_MODES = new Set(['dangerous', 'always', 'trusted'])

/** 归一化 Loader row 的 config（本插件不声明 Config schema）。 */
export function normalizeConfig(raw = {}) {
  const config = isPlainObject(raw) ? raw : {}
  return {
    dataDir: typeof config.dataDir === 'string' ? config.dataDir.trim() : '',
    defaultTimeoutSec: clampInt(config.defaultTimeoutSec, 5, 3600, 60),
    maxParallelHosts: clampInt(config.maxParallelHosts, 1, 32, 8),
    maxOutputBytes: clampInt(config.maxOutputBytes, 1024, 1048576, 32768),
    sessionIdleMinutes: clampInt(config.sessionIdleMinutes, 1, 1440, 30),
    approvalMode: APPROVAL_MODES.has(config.approvalMode) ? config.approvalMode : 'dangerous',
    extraDangerousPatterns: Array.isArray(config.extraDangerousPatterns)
      ? config.extraDangerousPatterns.filter((item) => typeof item === 'string')
      : [],
  }
}

export function apply(ctx, rawConfig = {}) {
  const config = normalizeConfig(rawConfig)
  const paths = createPaths(resolveDataDir(config.dataDir))
  const logger = console

  const inventory = createInventory({ filePath: paths.inventoryFile })
  const knownHosts = createKnownHosts({ filePath: paths.knownHostsFile })
  const credentials = ctx.get('credentials')
  const approval = ctx.get('approval')
  const secrets = createSecretStore({ credentials })
  const service = createService({
    config,
    paths,
    inventory,
    knownHosts,
    secrets,
    approval,
    logger,
  })
  const gate = createApprovalGate({ approval, mode: config.approvalMode, logger })

  installTools(ctx, { service, gate, config })
  ctx.inject(['connection'], (connectionCtx) => installRpc(connectionCtx, { service, logger }))
  ctx.inject(['systemPrompt'], (promptCtx) => installPrompt(promptCtx, { config, paths }))
  ctx.effect(() => () => {
    try {
      service.dispose()
    } catch (error) {
      logger.warn?.(`[remote-bash] 清理失败：${error?.message ?? error}`)
    }
  }, 'remote-bash.dispose')

  logger.info?.(
    `[remote-bash] ready · dataDir=${paths.root} · approval=${config.approvalMode} · credentials=${secrets.available() ? 'on' : 'off'}`,
  )
}
