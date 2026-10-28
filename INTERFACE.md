# Remote Bash · 内部接口

这份文档记录 Host 与 Client 之间、工具与测试之间的接口约定。改动 `host/`、`client.js` 或 `tests/` 时，请同步更新对应章节。

## 0. 目标与代码分布

一个 DSH bundle（Host + Client 两半），提供：

1. 单台/多台远程 Linux/macOS 主机的命令执行（SSH）；
2. 主机账户密码 / SSH 私钥认证，凭据存 DSH 内置凭据库（`ctx.credentials` 的 records 空间）；
3. 主机指纹 TOFU（首次自动记录并展示，之后变化拒绝）；
4. 危险命令执行前走 DSH 审批（`ctx.approval`）；
5. sudo 提权、持久会话（cd/export 跨调用保留）、SFTP 上传下载、主机分组/标签；
6. Web 设置页（`settings.section` 槽）管理主机、密码、指纹、会话。

代码分布：

- `index.js` / `host/`：Host 侧实现（工具、RPC、SSH、凭据、审批、持久会话）。
- `client.js`：浏览器侧设置页（`settings.section` 槽）。
- `tests/`：端到端测试与 mock SSH 服务器。
- `cordis.patch.yml`、`locale/`、`icon.svg`：bundle 元数据。
- `docs/images/`：README 配图。

## 1. 数据与存储（Host 侧）

- 数据目录：`config.dataDir`，为空时 = `$DSH_HOME/remote-bash`，`$DSH_HOME` 缺失时 `~/.dsh/remote-bash`。
- `inventory.json`（0600）：主机清单（不含任何密码）。
- `known_hosts.json`（0600）：TOFU 指纹。
- 密码/私钥/口令/sudo 密码：**DSH 内置凭据库 records**，地址 `remote-bash/<hostId>`，`kind: 'grant'`，`payload: {password?, passphrase?, privateKey?, sudoPassword?}`。Host 通过 `ctx.credentials` 的 `readRecord/modifyRecord/deleteRecord` 读写，值永不回传浏览器，也不进模型上下文。

### 主机记录（inventory.json 的 hosts 元素）

```js
{
  id: 'web-1',                  // 永久 id，slug：小写字母/数字/连字符，唯一
  name: 'web-1',                // 显示名，唯一
  host: '10.0.0.5',             // 必填，IP 或域名
  port: 22,                     // 1-65535，默认 22
  username: 'deploy',           // 必填
  auth: 'password',             // 'password' | 'key'
  keyPath: '',                  // auth='key' 时可填私钥文件路径；留空则用凭据库里的 privateKey 内容
  tags: ['web'],                // 分组/标签，可空数组
  note: '',
  sudo: false,                  // 该主机默认是否 sudo
  createdAt: 0,                 // epoch ms
  updatedAt: 0
}
```

### 指纹记录（known_hosts.json 的 hosts 元素）

```js
{
  host: '10.0.0.5',
  port: 22,
  keyType: 'ssh-ed25519',              // ssh2 parseKey(key).type
  fingerprint: 'SHA256:xxxx',          // OpenSSH 风格：'SHA256:' + base64(sha256(raw host key blob)) 去掉 '=' 填充
  firstSeenAt: 0,
  lastSeenAt: 0
}
```

## 2. Host 模块 API（测试直接 import）

所有模块都是 ESM，路径相对仓库根。参数只接受明文对象；错误用 `Error`，可带 `error.code`。

### 2.1 `host/paths.js`

```js
export function expandHome(input) -> absolutePath          // '~' / '~/x' / 普通路径
export function createPaths(dataDir) -> { root, inventoryFile, knownHostsFile }
```

### 2.2 `host/inventory.js`

```js
export function createInventory({ filePath })
  async load() -> { version: 1, hosts: Host[] }            // 文件不存在 => 空清单
  async list() -> Host[]
  async get(id) -> Host | undefined
  async upsert(input) -> Host                              // input 见下；校验失败抛 Error(code='invalid-host'|'duplicate-name')
  async remove(id) -> boolean
export function normalizeHostInput(input, { existing, others }) -> Host  // 纯函数，可单测
```

`upsert` 接受的 input：`{ id?, name, host, port?, username, auth, keyPath?, tags?, note?, sudo? }`。`id` 缺省时由 `name` slug 化生成（冲突加 `-2` 后缀）。

### 2.3 `host/knownhosts.js`

```js
export function fingerprintOf(hostKeyBuffer) -> 'SHA256:...'
export function keyTypeOf(hostKeyBuffer) -> string
export function createKnownHosts({ filePath })
  async find(host, port) -> entry | undefined
  async record({ host, port, keyType, fingerprint }) -> entry     // 新增或刷新 lastSeenAt
  async approve({ host, port, keyType, fingerprint }) -> entry    // 记录/更新为给定指纹
  async forget(host, port) -> boolean
  async list() -> entry[]
```

### 2.4 `host/credentials.js`（秘钥存储适配器）

```js
export function createSecretStore({ credentials })         // credentials 可为 undefined（服务缺失）
  available() -> boolean
  async read(hostId) -> { password?, passphrase?, privateKey?, sudoPassword? }   // 缺失返回 {}
  async flags(hostId) -> { available, configured, fields: { password, passphrase, privateKey, sudoPassword } } // 只回布尔
  async write(hostId, patch, { clear = [] } = {}) -> void  // patch 只覆盖出现的字段；clear 里列出的字段删除；全空则删 record
  async clear(hostId) -> void
export function recordKey(hostId) -> 'remote-bash/<hostId>'
```

### 2.5 `host/ssh.js`

```js
export function createSshClient({ knownHosts, logger })
  // 连接并完成 TOFU 校验；成功 resolve 的连接由调用方负责 end()
  async connect(host, secret, { timeoutMs = 15000, signal } = {})
    -> { client, fingerprint, keyType, hostKeyStatus: 'known'|'new', banner }
    // 失败抛 Error：
    //   code='host-key-changed' 时 error.details = { host, port, fingerprint, keyType, previousFingerprint }
    //   code='auth-failed' | 'connect-timeout' | 'connect-failed' | 'aborted'
  async exec(client, { command, timeoutMs, signal, maxOutputBytes = 32768 })
    -> { code: number|null, signal: string|null, output: string, truncated: boolean }
    // output = stdout + (stderr 非空时 "\n[stderr]\n" + stderr)；cap 后头尾保留、中间标注截断
export function buildCommand({ command, cwd, sudo, sudoPassword }) 
    -> { remoteCommand: string, stdin?: string }
    // cwd: 'cd <quoted> && (\n<command>\n)'
    // sudo:  "sudo -S -p '' -- bash -lc <quoted command>"，stdin = sudoPassword + '\n'
export function expandRemotePath(path, home) -> string     // '~/x' 用远端 $HOME 展开
export async function remoteHome(client) -> string         // exec 'printf %s "$HOME"'
```

### 2.6 `host/shell.js`（持久 shell）

```js
export async function openShell(client, { timeoutMs = 15000 } = {})
  -> ShellSession
class ShellSession
  async run(command, { timeoutMs, maxOutputBytes = 32768 })
    -> { code: number|null, output: string, truncated: boolean, timedOut: boolean }
  async close() -> void
  readonly alive: boolean
```

实现要点：`client.shell()` 打开 channel（不请求 PTY），先执行 `exec bash --noprofile --norc -s 2>/dev/null || exec sh -s`；每条命令用唯一 marker 包裹（`printf '\n__RB_BEGIN_<token>__\n'` / `printf '\n__RB_END_<token>:%s__\n' "$?"`），读到 END 为止；无 PTY 无回显。超时时写 `\x03` 尝试回到提示；仍不同步则销毁 session。

### 2.7 `host/danger.js`

```js
export const DEFAULT_PATTERNS = [ { id, label, pattern: RegExp }, ... ]
export function assessCommand(command, { extraPatterns = [] } = {})
  -> { dangerous: boolean, matches: [{ id, label }] }
```

默认覆盖：`rm -rf` 危险目标、`mkfs`、`dd of=/dev/*`、`shutdown/reboot/halt/poweroff`、`init 0/6`、`systemctl stop|disable|mask` 关键服务、`iptables -F`/`nft flush`、`userdel`/`groupdel`、`crontab -r`、递归 chmod/chown 系统目录、fork bomb、`fdisk/parted/wipefs`、`sudo` + 危险命令、`> /etc/*` 覆盖、`docker system prune`/`docker volume rm`、`truncate -s 0`。

### 2.8 `host/approval.js`

```js
export function createApprovalGate({ approval, mode, logger })
  // mode: 'dangerous' | 'always' | 'trusted'
  async check({ agent, toolName, callId, signal, command, hostNames, matches })
    -> { allowed: boolean, outcome: 'not-needed'|'allowed-once'|'rejected'|'cancelled'|'unavailable', reason? }
```

规则：`trusted` 永不放行审批；`always` 每条命令都问；`dangerous` 仅在 `matches.length > 0` 时问。审批服务缺失而需要审批时 => `allowed:false, outcome:'unavailable'`（失败关闭）。`ctx.approval.request({ agent, toolName, callId, reason, displayReason: { en, zh }, signal })`，只有 `'allowed-once'` 算通过。

### 2.9 `host/service.js`（核心，工具 / RPC / 测试共用）

```js
export function createService({ config, paths, inventory, knownHosts, secrets, approval, logger })
  // config: { dataDir, defaultTimeoutSec, maxParallelHosts, maxOutputBytes, sessionIdleMinutes,
  //           approvalMode, extraDangerousPatterns }（已归一化）
  // approval: ctx.approval 或 undefined
  // 返回对象方法见下；另有 dispose()（关闭全部连接/会话/定时器）
```

方法（**名字与返回结构固定**）：

| 方法 | 入参 | 返回 |
|---|---|---|
| `state()` | — | `State`（见 §4.1） |
| `saveHost(input)` | §2.2 input + `secret?: {password?,passphrase?,privateKey?,sudoPassword?}` + `clear?: string[]` | `{ host, state }` |
| `deleteHost({id})` | id | `{ removed: boolean, state }` |
| `testHost({ id?, draft?, secret? })` | 已存主机 id，或未保存草稿（结构同 §2.2 input）+ 临时 secret | `{ ok, elapsedMs, banner?, fingerprint, keyType, hostKeyStatus: 'known'\|'new'\|'changed', error?: {code,message,details} }` |
| `resolveTargets(targets)` | `'all'` / `'@tag'` / `'a,b'` | `Host[]`；空或未知抛 Error(code='unknown-target') |
| `run({ targets, command, cwd?, timeoutSec?, session?, sudo?, maxOutputBytes? })` | — | `RunResult`（见 §4.2） |
| `upload({ targets, localPath, remotePath, timeoutSec? })` | — | `TransferResult`（见 §4.3） |
| `download({ targets, remotePath, localPath, timeoutSec? })` | — | `TransferResult` |
| `listSessions({ agentId? })` | — | `SessionInfo[]`（§4.4） |
| `closeSession({ key })` | — | `boolean` |
| `closeAllSessions()` | — | `number` |
| `knownHostsState()` | — | `KnownHost[]`（§4.5） |
| `forgetKnownHost({ host, port })` | — | `boolean` |
| `approveFingerprint({ host, port, fingerprint? })` | 需与最近一次 `testHost` 捕获的 pending 指纹一致；省略 fingerprint 时用 pending | `{ entry, state }` |

`run`/`upload`/`download` 内并发上限 `config.maxParallelHosts`；单机异常不影响其他主机；返回每个主机的独立结果。

### 2.10 `host/plugin.js` / `host/rpc.js` / `host/tools.js` / `host/prompt.js`

- `plugin.js`：`export const name='remote-bash'`、`export const inject=['tools']`、`export function apply(ctx, config)`。把 `ctx.get('credentials')`、`ctx.get('approval')` 注入 service；`ctx.effect` 管 RPC 与工具的清理；`ctx.inject(['connection'], ...)` 装 RPC，`ctx.inject(['systemPrompt'], ...)` 装提示词。
- `rpc.js`：`export const RPC_ENDPOINT = 'remote-bash/rpc'`、`export function installRpc(ctx,{service})`。复用 `ctx.connection.fetch.register({ path: '/api/remote-bash/rpc', methods: ['POST'], requestBody: 'buffered', fetch })`，envelope 为 DSH 的 client-request / server-response 结构（`rpcId`、`method`、`payload`、`result: {ok, value|error}`）。
- `tools.js`：`export function installTools(ctx, { service, gate, config })`，注册 5 个工具（§5）。
- `prompt.js`：`export function installPrompt(ctx, { config, paths })`，`ctx.systemPrompt.section({ name:'remote-bash', order: 530, text })`。

## 3. 浏览器 → Host RPC（Client 侧调用）

调用方式（client 侧）：

```js
rpcCall = (method, payload, signal) =>
  ctx.connection.rpc.call('/api', 'remote-bash/rpc', { method, payload: payload ?? {} }, signal)
```

成功：`{ ok: true, value }`；失败：`{ ok: false, error: { code, message, details } }`。UI 需把错误展示为 banner/toast，`code` 可用于分支。

### RPC 方法清单

| method | payload | value |
|---|---|---|
| `state` | `{}` | `State`（§4.1） |
| `host.save` | §2.2 input + `secret?` + `clear?: string[]`（secret 只在用户当次输入时传） | `{ host, state }` |
| `host.delete` | `{ id }` | `{ removed, state }` |
| `host.test` | `{ id }` 或 `{ draft, secret }` | `testHost` 返回值（§2.9） |
| `knownHost.forget` | `{ host, port }` | `{ removed, state }` |
| `knownHost.approve` | `{ host, port, fingerprint? }` | `{ entry, state }` |
| `session.close` | `{ key }` | `{ closed, state }` |
| `session.closeAll` | `{}` | `{ closed: number, state }` |

RPC 参数走 JSON；`secret` 里可能出现明文密码（本机 loopback + DSH 鉴权连接），Host 收到后只写凭据库，不回传、不打印日志。

## 4. 返回结构（固定）

### 4.1 `State`

```js
{
  settings: { dataDir, approvalMode, defaultTimeoutSec, maxParallelHosts, maxOutputBytes, sessionIdleMinutes },
  credentialsAvailable: boolean,
  hosts: [{
    id, name, host, port, username, auth, keyPath, tags, note, sudo, createdAt, updatedAt,
    secret: { available, configured, fields: { password, passphrase, privateKey, sudoPassword } } // 全布尔
  }],
  groups: [{ tag, hostIds: string[] }],
  knownHosts: [{ host, port, keyType, fingerprint, firstSeenAt, lastSeenAt }],
  sessions: [{ key, label, hostId, hostName, agentId, createdAt, lastUsedAt }]
}
```

### 4.2 `RunResult`

```js
{
  command, cwd: string|null, session: string|null, sudo: boolean,
  startedAt: number, durationMs: number,
  hosts: [{
    hostId, name, host, port, username,
    status: 'ok' | 'error' | 'timeout',
    exitCode: number|null, signal: string|null,
    output: string, truncated: boolean, durationMs: number,
    error?: { code, message },
    fingerprint?: string, keyType?: string, hostKeyStatus?: 'known'|'new'
  }]
}
```

### 4.3 `TransferResult`

```js
{
  action: 'upload' | 'download', localPath, remotePath, durationMs,
  hosts: [{ hostId, name, status: 'ok'|'error', bytes, durationMs, error?: {code,message} }]
}
```

路径模板：`remotePath` / `localPath` 支持 `{host}`、`{name}`、`{id}`、`{basename}` 占位符；多主机下载到 `localPath` 目录时文件名为 `<name>-<basename>`（或保留目录结构在 `<name>/` 下）。

### 4.4 `SessionInfo`

```js
{ key, label, hostId, hostName, agentId, createdAt, lastUsedAt }
```

key 形如 `<agentId>::<label>::<hostId>`。

### 4.5 `KnownHost`

同 §1 指纹记录元素。

## 5. Agent 工具（模型可见）

| 工具 | 参数 | 说明 |
|---|---|---|
| `remote_bash` | `{ targets: string, command: string, description?: string, cwd?: string, timeoutSec?: number, session?: string, sudo?: boolean, maxOutputBytes?: number }` | `description`：一句话中文命令目的，显示在审批弹窗与会话卡片；危险命令走审批。返回摘要文本（含 description） |
| `remote_hosts` | `{}` | 列出已配置主机：名字、id、用户@地址:端口、认证方式、分组、凭据是否已配置 |
| `remote_upload` | `{ targets, localPath, remotePath, timeoutSec? }` | SFTP 上传（文件或目录递归） |
| `remote_download` | `{ targets, remotePath, localPath, timeoutSec? }` | SFTP 下载 |
| `remote_sessions` | `{ action: 'list'|'close', session?: string }` | 持久会话管理（只操作本 agent 的会话） |

工具 `execute(args, exec)` 内可用：`exec.agent`（Agent）、`exec.callId`、`exec.signal`。审批 gate 在工具层调用；审批拒绝时抛出 `Error('已拒绝执行...')`。

## 6. 设置页 UI 规格

**注册**（client.js）：

```js
ctx.slots.inject('settings.section', () => ctx.slots.register({
  name: 'settings.section',
  id: 'remote-bash',
  order: 30,
  label: () => translate('settings.title'),
}, RemoteBashSection))
```

`dsh.client` 清单已在 package.json（platform web / immediately / inject connection+locale），不用改。

**页面结构**（单文件，React.createElement，无构建步骤）：

1. 顶部标题 + 一句话说明 + 「添加主机」按钮 + 刷新按钮；数据加载失败显示错误 banner + 重试。
2. 三个分段（segmented tabs）：主机 / 已知主机 / 会话；默认主机。
3. 主机页：
   - 空态：说明 + 添加按钮。
   - 按 tag 分组显示（无 tag 归「未分组」）；每行：名称、`user@host:port`、认证方式徽标（密码/私钥）、tag chips、凭据状态（密码已设置/未设置，私钥/口令同理）、按钮：测试连接 / 编辑 / 删除（删除需二次确认弹窗）。
   - 添加/编辑弹窗表单字段：名称*、主机地址*、端口（默认 22）、用户名*、认证方式（密码/私钥 radio 或 select）、密码（type=password，已设置时占位「已设置，留空不修改」）、私钥文件路径（auth=key 时）、私钥内容（textarea，可选，替代路径）、私钥口令、sudo 密码、分组标签（逗号分隔）、备注、默认 sudo（switch）。密码类字段旁有「清除」按钮（调 host.save 带 clear）。
   - 保存后展示结果 banner（成功/失败原因）。
   - 测试连接：按钮 loading；结果展示 elapsedMs、banner、fingerprint、hostKeyStatus（首次=「已自动记录指纹」；changed=「指纹变化，已拒绝」+ 「信任新指纹」按钮调 knownHost.approve）。
4. 已知主机页：列表显示 host:port、keyType、fingerprint（等宽字体）、firstSeenAt、忘记按钮（二次确认）。
5. 会话页：列表显示 label、hostName、agentId（截断）、创建/最近使用时间、关闭按钮；「全部关闭」。说明持久会话会在空闲后自动关闭。
6. 所有可见文案走 `ctx.locale`（自建 zh/en 字典，与 DSH 现有插件一致），样式只用 `--dsw-alias-*` token（用 `cordis_inspect_query` client Theme 查可用 token 名），不引入任何 Harness Client 包 import。
7. 弹窗自己实现：遮罩 + 卡片、Escape 关闭、初始焦点、`role="dialog"` + `aria-modal`；不写 `document.body`，不用 `confirm()`。
8. 不要发宿主页面没有的请求；不要轮询超过 3s 一次（有需要就手动刷新）。
9. 语法检查：`node --check client.js` 必须通过。

参考实现（DSH 安装目录下）：

- `@deepseek-ai/dsh-client-ui-settings-general/lib/client.js`：`settings.section` 的布局与样式惯例。
- `@deepseek-ai/dsh-client-ui-settings/lib/client.js`：slot 契约与表单写法。

## 7. 测试 fixture 规格

目标：不依赖真实远程主机，用 `ssh2` 在 127.0.0.1 起一个真实 SSH 服务器，对 `host/**` 做端到端测试。

`tests/mock-ssh-server.mjs` 要求：

- `createMockServer({ dataDir, hostKey })` → `{ listen(): Promise<{port, close(), fingerprint, setHostKey(key)}> }`；只监听 127.0.0.1，端口 0。
- 主机密钥：`ssh2.utils.generateKeyPairSync('ed25519')` 生成；`hostKeys` 支持热替换（用于测试指纹变化）。
- 认证：password `tester/secret`；publickey：接受 fixture 公钥（含带 passphrase 的私钥场景）。
- `exec`：`/bin/bash -c <command>`，cwd = 每连接临时目录，环境最小化（HOME 指向临时目录）；`sudo -S -p '' -- bash -lc '...'` 拦截：读 stdin 第一行当密码，等于 `sudoPassword` 时去 sudo 前缀执行，否则 stderr `sudo: a password is required` 退出 1。
- `shell`：spawn `/bin/bash -s`，双向 pipe（持久会话测试 cd/export）。
- `sftp`：映射到数据目录，实现 OPEN/READ/WRITE/CLOSE/STAT/LSTAT/FSTAT/REALPATH/OPENDIR/READDIR/MKDIR/RMDIR/REMOVE/RENAME（fastPut/fastGet 所需即可）。
- 指纹：`SHA256:base64(sha256(hostKeyBlob))`，可用 `ssh-keygen -lf <fixture.pub>` 交叉验证格式。

`tests/*.test.mjs` 用 `node:test` + `node:assert/strict`；`npm test` 必须全绿。fake 依赖：

```js
const fakeCredentials = { records: new Map(), async readRecord(key){...}, async modifyRecord(key, mutate){...}, async deleteRecord(key){...} }
const fakeApproval = { calls: [], async request(req){ this.calls.push(req); return 'allowed-once' } }
```

必须覆盖：清单 CRUD/校验、指纹 TOFU（新增后 known；换 host key 后 `host-key-changed`；approve 后可连）、密码认证、私钥认证、单机 exec、多机并行 exec 且单机失败互不影响、超时、持久会话 cd/export 保留、sudo 密码正确/错误、SFTP 文件与目录上传下载、危险命令识别、凭据读写与清除、多主机 targets（`all` / `@tag` / 逗号分隔）。所有文件写到 `os.tmpdir()` 下的临时目录，测试结束清理。

## 8. 提交前检查

- `npm test` 全绿，`node --check client.js` 通过。
- 改动 Host 侧接口时同步更新本文档。
- 只提交源码、测试与文档，不要提交 `node_modules/`、本地数据目录或凭据。

## 9. 补充与修正（以此节为准）

以下是实现过程中对前文的补充与修正，测试按此断言：

1. `host/ssh.js`：`exec` 现在导出为 `execChannel(client, opts)`，返回 `{ code, signal, output, truncated, timedOut, aborted }`（多 `timedOut`/`aborted`）；`createSshClient()` 返回 `{ connect, exec: execChannel }`。
2. `buildCommand({command,cwd,sudo,sudoPassword})` 只返回 `{ remoteCommand }`（**没有 stdin**）。sudo 通过 heredoc 提供密码：`sudo -S -p '' -- bash -lc '<cmd>' <<'<delim>'`；密码为空/含换行分别抛 `sudo-password-missing` / `invalid-secret`。`cwd` 支持 `~`、`$HOME`（由远端 shell 展开，`cdTarget()` 实现）。
3. `host/ssh.js` 新增 `remoteStat(client, target)` → `{ isDirectory, isFile, size } | null`。
4. `service.run/upload/download` 的 opts 均接受可选 `signal`（工具取消）。
5. `service.testHost`：指纹变化返回 `{ ok:false, hostKeyStatus:'changed', error:{code:'host-key-changed', details} }`；其它失败返回 `hostKeyStatus:'unknown'`。`approveFingerprint` 需要先由 `testHost` 捕获 pending 指纹。
6. `service.closeAllSessions()` 返回关闭数量；`service.state().sessions` 含 `hostName`。
7. 多主机下载已实现契约 §4.3：无 `{host}/{name}/{id}` 模板时，文件存为 `<localPath>/<name>-<basename>`，目录存到 `<localPath>/<name>/`；单主机 `localPath` 以 `/` 结尾且远端为文件时自动拼接 basename。transfer 的 host 条目额外带 `localPath`/`remotePath`（实际使用值）。
8. `host/sessions.js`：会话 key = `<agentId>::<label>::<hostId>`；persistent shell 命令超时会关闭该会话并返回 `timedOut:true`、`sessionClosed:true`；上限 64 个会话，LRU 淘汰；空闲 `sessionIdleMinutes` 回收。
9. `tests/mock-ssh-server.mjs`：SFTP 越界判断需对内层路径做 `realpathSync.native`（`/var` → `/private/var` 符号链接），否则绝对路径会误报 Permission denied；自测脚本要显式清理并退出。
10. 工具层：`sudo:true` 或任一目标主机默认 `sudo` 时会追加 `sudo 提权` 风险项（`sudo-mode`），因此会触发审批（`approvalMode=trusted` 时除外）。
11. 持久会话 stderr：`ShellSession.init()` 用 `command -v bash >/dev/null 2>&1 && exec bash ... || exec sh ...`，重定向只作用于探测命令，会话内命令的 stderr 正常返回并合并为 `[stderr]` 段。
12. danger 规则：新增 `rm-system-path`（递归强制删除系统目录 / 家目录关键隐藏目录）；`rm-dangerous` 覆盖 `/`、`/*`、`~`、`~/*`、`$HOME`、`*`、`..`、`.`、`--no-preserve-root`。`rm -rf /tmp/x`、`rm -rf ./dist`、`rm -rf ~/project/dist` 有意不拦。
13. 下载本地目标解析：无模板时按远端类型与主机数量命名（多主机文件 `<name>-<basename>`、多主机目录 `<name>/`；单主机 localPath 为已存在目录或以 `/` 结尾时落到目录内同名文件）。

14. 审批可读性：`remote_bash` 新增 `description` 参数（模型每次执行命令填写一句中文目的）；`approval.check` 接收 description，用户可见的 `displayReason` 只含「在 N 台主机（列表）执行「目的」· 风险：规则，是否允许？」，不再内嵌命令；审计用 `reason` 保留 description + 完整命令（截断 300 字符）。`presentCall.description` 优先用 description，`renderRun` 输出「说明：…」行。
15. danger 修正：`etc-overwrite` 旧正则会误匹配"重定向到 /dev/null 后任意位置出现 /var/lib/..."（用户 `du /var/lib/docker` 被误判为"覆盖系统配置"）。现要求重定向/tee 的目标紧跟系统目录（`> /etc/...`、`tee /etc/...`），并加了回归用例。
