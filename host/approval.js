/**
 * 执行前审批门：把危险命令或全部命令交给 DSH 审批服务（ctx.approval）。
 * 只有 'allowed-once' 算通过；审批服务缺失时失败关闭。
 */
import { errorWithCode } from './util.js'

function shorten(text, max = 400) {
  const value = String(text ?? '')
  return value.length > max ? `${value.slice(0, max)}…` : value
}

export function createApprovalGate({ approval, mode = 'dangerous', logger = console }) {
  const available = Boolean(approval && typeof approval.request === 'function')

  return {
    mode,
    available,
    async check({ agent, toolName = 'remote_bash', callId, signal, command, description, hostNames = [], matches = [] }) {
      const needsApproval = mode === 'always' || (mode === 'dangerous' && matches.length > 0)
      if (!needsApproval) return { allowed: true, outcome: 'not-needed' }
      if (!available || !agent) {
        return {
          allowed: false,
          outcome: 'unavailable',
          reason: 'DSH 审批服务不可用，已拒绝需要审批的远程命令。',
        }
      }
      const targets = hostNames.join('、')
      const labels = matches.map((match) => match.label).join('、')
      const intent = typeof description === 'string' && description.trim()
        ? description.trim().slice(0, 200)
        : '远程命令'
      // 审计日志保留完整命令；用户可见的 displayReason 只放简短意图，避免弹窗里出现大段命令。
      const reason = `Remote Bash 在 ${hostNames.length} 台远程主机（${targets}）执行：${intent}${
        labels ? `（命中风险规则：${labels}）` : ''
      }\n命令：${shorten(command, 300)}`
      const displayReason = {
        zh: `在 ${hostNames.length} 台主机（${targets}）执行「${intent}」${labels ? ` · 风险：${labels}` : ''}，是否允许？`,
        en: `Run "${intent}" on ${hostNames.length} host(s) (${targets})${labels ? ` · risk: ${labels}` : ''}. Allow once?`,
      }
      let outcome
      try {
        outcome = await approval.request({
          agent,
          toolName,
          callId,
          reason,
          displayReason,
          signal,
        })
      } catch (error) {
        logger.warn?.(`[remote-bash] 审批请求失败：${error?.message ?? error}`)
        return {
          allowed: false,
          outcome: 'unavailable',
          reason: `审批请求失败：${error?.message ?? error}`,
        }
      }
      if (outcome === 'allowed-once') return { allowed: true, outcome }
      const messages = {
        rejected: '用户拒绝了这次远程命令执行。',
        cancelled: '审批被取消，命令未执行。',
        unavailable: '审批通道不可用，命令未执行。',
      }
      return {
        allowed: false,
        outcome,
        reason: messages[outcome] ?? `审批未通过（${outcome}），命令未执行。`,
      }
    },
  }
}

/** 便捷包装：不允许时抛出带 code 的错误。 */
export async function requireApproval(gate, request) {
  const result = await gate.check(request)
  if (!result.allowed) throw errorWithCode('approval-denied', result.reason || '命令未获批准。')
  return result
}
