/**
 * Remote Bash · Host 入口。
 *
 * 真实装配在 host/plugin.js：主机清单 + 凭据存储 + SSH 连接池 + 持久会话 +
 * SFTP + 危险命令审批 + Agent 工具 + 浏览器 RPC。这里只保留 DSH Loader 需要的
 * 导出形态。
 */
export { name, inject, apply } from './host/plugin.js'
