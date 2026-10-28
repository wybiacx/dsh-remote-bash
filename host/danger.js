/**
 * 危险命令识别：命中即触发 DSH 审批（approvalMode='dangerous' 时）。
 * 规则尽量聚焦"不可逆/影响系统可用性/提权"的操作，避免把普通命令也拖进审批。
 */

export const DEFAULT_PATTERNS = [
  { id: 'rm-dangerous', label: '递归删除危险路径', pattern: /\brm\s+(?:-[a-zA-Z]+\s+)+(?:--no-preserve-root\s+)?(?:\/|\/\*|~\/?\*?|\$HOME\/?\*?|\*|\.\.?)(?:\s|$)/ },
  { id: 'rm-system-path', label: '删除系统/家目录关键路径', pattern: /\brm\s+-[a-zA-Z]*(?:[rR][a-zA-Z]*[fF]|[fF][a-zA-Z]*[rR])[a-zA-Z]*\s+(?:-[a-zA-Z]+\s+)*(?:\/(?:etc|usr|bin|sbin|lib|lib64|boot|var|opt|root|home|Users|System|Library|private)\b|~\/(?:\.ssh|\.gnupg|\.config|\.local|\.cache|\.aws|\.kube|\.docker|\.npm|\.vnc|\.bashrc|\.zshrc)\b|\$HOME\/(?:\.ssh|\.gnupg|\.config|\.local|\.cache|\.aws|\.kube|\.docker|\.npm)\b)/ },
  { id: 'mkfs', label: '格式化文件系统', pattern: /\bmkfs(?:\.\w+)?\b/ },
  { id: 'dd-device', label: '直接写块设备', pattern: /\bdd\b[^\n]*\bof=\/dev\// },
  { id: 'shutdown', label: '关机/重启', pattern: /\b(?:shutdown|reboot|halt|poweroff)\b/ },
  { id: 'init-runlevel', label: '切换运行级别', pattern: /\binit\s+[06]\b/ },
  { id: 'systemctl-critical', label: '停止关键服务', pattern: /\bsystemctl\s+(?:stop|disable|mask|restart)\s+[\w.@-]*(?:sshd?|networking|network|NetworkManager|firewalld|ufw|docker|containerd|nginx|apache2|httpd|mysql|mariadb|postgresql|redis|kubelet)\b/i },
  { id: 'firewall-flush', label: '清空防火墙规则', pattern: /\b(?:iptables|ip6tables|nft)\b[^\n]*\s(?:-F|flush)\b/ },
  { id: 'user-admin', label: '账户/密码管理', pattern: /\b(?:userdel|groupdel|usermod|chpasswd|passwd|visudo)\b/i },
  { id: 'crontab-remove', label: '清空计划任务', pattern: /\bcrontab\s+-r\b/ },
  { id: 'recursive-perm', label: '递归修改系统权限', pattern: /\bch(?:mod|own|grp)\b[^\n]*-R[^\n]*\s\/(?:etc|usr|var|bin|sbin|lib|boot|home|root|opt)\b/ },
  { id: 'fork-bomb', label: 'fork 炸弹', pattern: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/ },
  { id: 'disk-partition', label: '磁盘分区操作', pattern: /\b(?:fdisk|gdisk|parted|sgdisk|wipefs|mkswap)\b/ },
  { id: 'etc-overwrite', label: '覆盖系统配置', pattern: /(?:>>?\s*|\btee\s+(?:-\S+\s+)*)\/(?:etc|boot|bin|sbin|usr|lib)\// },
  { id: 'docker-destructive', label: 'Docker 破坏性操作', pattern: /\bdocker\s+(?:system\s+prune|volume\s+(?:rm|prune)|container\s+prune|image\s+prune)\b/ },
  { id: 'truncate-zero', label: '清空文件内容', pattern: /\btruncate\b[^\n]*-s\s*0\b/ },
  { id: 'kill-init', label: '强制杀 init 进程', pattern: /\bkill\s+-9\s+1\b/ },
  { id: 'sudo', label: 'sudo 提权', pattern: /\bsudo\b/ },
]

/** 编译 config.extraDangerousPatterns（字符串正则），非法项忽略。 */
export function compileExtraPatterns(extraPatterns = [], logger = console) {
  const compiled = []
  let index = 0
  for (const raw of Array.isArray(extraPatterns) ? extraPatterns : []) {
    if (typeof raw !== 'string' || !raw.trim()) continue
    try {
      compiled.push({ id: `extra-${index++}`, label: `自定义规则 ${index}`, pattern: new RegExp(raw) })
    } catch (error) {
      logger.warn?.(`[remote-bash] 忽略非法的 extraDangerousPatterns：${raw}（${error?.message ?? error}）`)
    }
  }
  return compiled
}

export function assessCommand(command, { extraPatterns = [] } = {}) {
  const text = String(command ?? '')
  const patterns = [...DEFAULT_PATTERNS, ...compileExtraPatterns(extraPatterns)]
  const matches = []
  for (const rule of patterns) {
    if (rule.pattern.test(text)) matches.push({ id: rule.id, label: rule.label })
  }
  return { dangerous: matches.length > 0, matches }
}
