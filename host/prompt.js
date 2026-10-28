/**
 * 系统提示词段落：告诉模型什么时候用 Remote Bash 工具、参数约定与安全边界。
 * 只放稳定约定，不放每次执行都可能变化的主机详情（按需用 remote_hosts 读取）。
 */
export function installPrompt(ctx, { config, paths }) {
  const lines = [
    '【Remote Bash · 远程主机命令执行】',
    `- 已配置的远程 Linux/macOS 主机由用户在 DSH 设置 → Remote Bash 中维护；插件数据在 ${paths.root}。不要用 shell 直接读取该目录里的文件。`,
    '- 需要知道有哪些主机、分组、凭据是否配置时，用 `remote_hosts`；不要编造主机名。',
    '- 在远程主机执行命令用 `remote_bash`：`targets` 支持主机名/id（逗号分隔）、`@分组名`、`all`；一次调用对多台主机并行执行同一命令。',
    '- 每次调用 `remote_bash` 都要填 `description`：一句话中文说明命令目的（如「查看磁盘占用」「重启 nginx」）；它显示在审批弹窗和会话卡片里，比裸命令更容易让用户确认。',
    '- 需要保留 cd/export 等 shell 状态时传 `session`（同一 session 名跨调用复用同一个 shell）；一次性命令不要传。',
    '- 提权用 `sudo: true`（使用该主机保存的 sudo 密码/登录密码）；能用普通用户完成就不要提权。',
    '- 危险命令（rm -rf 危险路径、mkfs、dd 写设备、关机、停关键服务、改账户、清防火墙、sudo 等）会先请求用户审批；被拒绝时如实告知用户，不要绕过。',
    '- 传输文件用 `remote_upload` / `remote_download`（SFTP，支持文件与目录）；`localPath` 用绝对路径最稳妥，远端路径支持 `~`。',
    '- 查看或关闭持久会话用 `remote_sessions`。',
    '- 若返回 `host-key-changed`：说明主机指纹变化被拒绝，提醒用户到 DSH 设置 → Remote Bash 的「已知主机 / 测试连接」确认新指纹后再试；不要建议用户关闭校验。',
    '- 绝不把密码、私钥内容写进命令或输出里；也不要向用户索要密码后用自己的工具存 —— 让用户在设置页录入。',
    `- 当前审批模式：${config.approvalMode === 'always' ? '所有远程命令都需要审批' : config.approvalMode === 'trusted' ? '不请求审批（用户已选择信任）' : '仅危险命令需要审批'}。`,
  ]
  return ctx.systemPrompt.section({
    name: 'remote-bash',
    order: 530,
    text: lines.join('\n'),
  })
}
