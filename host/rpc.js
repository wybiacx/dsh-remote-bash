/**
 * 浏览器 ↔ Host 的 Remote Bash RPC 通道。
 * 复用 DSH 连接层已鉴权的 /api 载体：Host 注册精确 fetch 路由
 * `/api/remote-bash/rpc`，浏览器侧用 `connection.rpc.call('/api','remote-bash/rpc',…)`。
 */
export const RPC_ENDPOINT = 'remote-bash/rpc'

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function reply(rpcId, result) {
  const value = result.ok === false
    ? { ...result, error: { ...result.error, details: result.error.details ?? {} } }
    : result
  return Response.json({ type: 'server-response', rpcId, result: value })
}

function publicError(error) {
  const code = typeof error?.code === 'string' && error.code ? error.code : 'internal'
  const message = typeof error?.message === 'string' && error.message ? error.message : '操作失败'
  const details = isRecord(error?.details) ? error.details : {}
  return { ok: false, error: { code, message, details } }
}

export function installRpc(ctx, { service, logger = console }) {
  const connection = ctx.get('connection')
  if (!connection?.fetch?.register) {
    logger.warn?.('[remote-bash] connection.fetch 不可用，设置页面数据通道未注册（Agent 工具仍可用）。')
    return () => {}
  }

  const handlers = {
    state: () => service.state(),
    'host.save': (payload) => service.saveHost(payload),
    'host.delete': (payload) => service.deleteHost(payload),
    'host.test': (payload) => service.testHost(payload),
    'knownHost.forget': (payload) => service.forgetKnownHost(payload),
    'knownHost.approve': (payload) => service.approveFingerprint(payload),
    'session.close': async (payload) => {
      const closed = await service.closeSession(payload)
      return { closed, state: await service.state() }
    },
    'session.closeAll': async () => {
      const closed = await service.closeAllSessions()
      return { closed, state: await service.state() }
    },
  }

  async function dispatch(method, payload) {
    const handler = Object.hasOwn(handlers, method) ? handlers[method] : undefined
    if (!handler) {
      const error = new Error(`未知的 RPC 方法：${method}`)
      error.code = 'unknown-method'
      throw error
    }
    return handler(isRecord(payload) ? payload : {})
  }

  const route = {
    path: `/api/${RPC_ENDPOINT}`,
    methods: ['POST'],
    requestBody: 'buffered',
    async fetch(request) {
      if (request.method !== 'POST') return new Response('method not allowed', { status: 405 })
      const contentType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase()
      if (contentType !== 'application/json') {
        return new Response('content type must be application/json', { status: 415 })
      }
      let message
      try {
        message = await request.json()
      } catch {
        return new Response('body is not JSON', { status: 400 })
      }
      const rpcId = typeof message?.rpcId === 'string' ? message.rpcId : 'invalid-request'
      const call = message?.payload
      if (!isRecord(message) || message.type !== 'client-request'
        || typeof message.rpcId !== 'string' || message.method !== RPC_ENDPOINT
        || !isRecord(call) || typeof call.method !== 'string'
        || !Object.hasOwn(call, 'payload')) {
        return reply(rpcId, {
          ok: false,
          error: { code: 'bad-request', message: 'Invalid Remote Bash RPC request.', details: {} },
        })
      }
      try {
        const value = await dispatch(call.method, call.payload)
        return reply(rpcId, { ok: true, value })
      } catch (error) {
        return reply(rpcId, publicError(error))
      }
    },
  }

  return ctx.effect(() => {
    let dispose = null
    let disposed = false
    connection.fetch.register(route)
      .then((fn) => {
        if (disposed) fn?.()
        else dispose = fn
      })
      .catch((error) => {
        logger.error?.('[remote-bash] 注册设置页面数据通道失败', error)
      })
    return () => {
      disposed = true
      try {
        dispose?.()
      } catch (error) {
        logger.warn?.('[remote-bash] 清理设置页面数据通道失败', error)
      }
    }
  }, 'remote-bash.rpc')
}
