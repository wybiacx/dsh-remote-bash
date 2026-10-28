/**
 * 数据目录解析。所有插件数据文件都必须经过这里，客户端永远不会传路径。
 */
import os from 'node:os'
import path from 'node:path'

/** 展开 `~` / `~/x` 为绝对路径。 */
export function expandHome(input) {
  if (typeof input !== 'string') return ''
  let value = input.trim()
  if (!value) return ''
  if (value === '~') return os.homedir()
  if (value.startsWith('~/')) value = path.join(os.homedir(), value.slice(2))
  else if (value.startsWith('~')) value = path.join(os.homedir(), value.slice(1))
  return path.resolve(value)
}

/**
 * 解析数据目录：插件 config.dataDir 优先，其次 <DSH_HOME>/remote-bash，
 * DSH_HOME 缺失时回落 ~/.dsh/remote-bash。
 */
export function resolveDataDir(dataDir) {
  const configured = typeof dataDir === 'string' ? dataDir.trim() : ''
  if (configured) return expandHome(configured)
  const home = typeof process.env.DSH_HOME === 'string' && process.env.DSH_HOME.trim()
    ? expandHome(process.env.DSH_HOME)
    : path.join(os.homedir(), '.dsh')
  return path.join(home, 'remote-bash')
}

/** 数据目录下的固定文件集合。 */
export function createPaths(dataDir) {
  const root = resolveDataDir(dataDir)
  return {
    root,
    inventoryFile: path.join(root, 'inventory.json'),
    knownHostsFile: path.join(root, 'known_hosts.json'),
    logFile: path.join(root, 'remote-bash.log'),
  }
}
