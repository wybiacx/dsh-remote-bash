# Remote Bash · 内部接口

Host、Client 与测试的契约。修改实现时同步更新本文档；工具仍为 `remote_bash`、`remote_hosts`、`remote_upload`、`remote_download`、`remote_sessions`。

## 1. 存储与升级

默认目录是 `$DSH_HOME/remote-bash`，缺失时使用 `~/.dsh/remote-bash`，可由 `dataDir` 覆盖。当前存储按单个 Host 实例管理；不要让多个运行中的 Host 同时共享同一数据目录。

`inventory.json`（0600）结构：

```js
{
  version: 2,
  hosts: [{
    id, name, host, port, username, auth, keyPath, tags, note, sudo,
    createdAt, updatedAt, revision,
    credentialRef: 'remote-bash/refs/<UUID>' // 或旧版 remote-bash/<hostId>，无凭据为 null
  }],
  pendingCleanup: [{ ref, id, name }]
}
```

- 原有主机 ID 保留；新主机 ID 为截断名称 slug 加 UUID，删除后同名新建不复用身份。名称、ID、`@tag`、`all` 均可用于工具目标。
- version 1 读取时将旧主机映射到 `remote-bash/<hostId>`；首次写入前生成 `inventory.json.v1.bak`，备份只包含已知的非秘密字段。未知版本拒绝读取/改写。
- 主机和凭据分别存储。保存先登记待清理的新引用、写新凭据记录，再原子提交主机与新引用，同时登记旧引用待清理。提交失败保留旧配置；提交后清理失败返回警告。
- 删除原子移除主机并登记其凭据待清理，再关闭会话和清理凭据。清理失败不重新挂载主机、不将残留凭据绑定给新身份。
- 启动只恢复清理日志中且未被活动主机引用的记录；不扫描并删除来源不明的旧版孤儿凭据。
- 不支持将 version 2 文件交给旧插件继续写入；v1 清单备份不包含凭据，不构成独立完整回滚备份。

秘密始终存于 DSH `credentials` records 空间，`kind: 'grant', payload: {password?, passphrase?, privateKey?, sudoPassword?}`。清单、日志、工具结果和浏览器响应不包含这些值。内部 `credentialRef/revision/expectedRevision` 不进入公开 Host 对象。

`known_hosts.json` 保持 version 1：`{version:1,hosts:[{host,port,keyType,fingerprint,firstSeenAt,lastSeenAt}]}`。首次信任与后续比较在同一串行操作内完成。

## 2. 存储模块

### inventory

```js
createInventory({ filePath })
  load() -> { version: 2, hosts, pendingCleanup }
  list() -> Host[]
  get(id) -> Host | undefined
  prepare(input) -> Host & { expectedRevision: number | null }
  commitHost(prepared, { retireRefs: string[] } = {}) -> Host
  removeAndRetire(id) -> { removed, host? }
  listPendingCleanup() -> [{ ref, id, name }]
  queueCleanup(entries) -> pendingCleanup
  completeCleanup(refs) -> pendingCleanup
  upsert(input) -> Host // 兼容包装；服务的含凭据保存使用 prepare/commit
  remove(id) -> boolean
```

`prepare/commitHost` 进行名称唯一性校验和记录 revision 比较；旧 prepared 对象不能覆盖新版本或复活已删除主机。清理列表不能包含活动凭据引用。输入字段：`{id?,name?,host?,port?,username?,auth?,keyPath?,tags?,note?,sudo?}`；新建的必填字段为名称、地址、用户名。

### credentials

```js
createSecretStore({ credentials })
  available() -> boolean
  createRef() -> 'remote-bash/refs/<UUID>'
  readRef(ref) -> Secret
  flagsRef(ref) -> { available, configured, fields }
  stage(baseRef, patch, {clear = [], ref} = {}) -> newRef | null
  clearRef(ref) -> void
  read(hostId) / flags(hostId) / write(hostId, patch, {clear}) / clear(hostId)
```

`stage` 写完整合并快照到独立记录，空快照返回 null。旧 `write` 在 `modifyRecord(current)` 内合并；清空全部字段保留空 grant，以避免额外 delete 误删并发更新；显式 `clear/clearRef` 才删除记录。`modifyRecord` 返回 undefined 是“不修改”，不是删除。

### knownhosts

`verify({host,port,keyType,fingerprint}) -> {fingerprint,keyType,status:'new'|'known'}`，异指纹抛 `host-key-changed`，details 包含 `{host,port,fingerprint,keyType,previousFingerprint}`。`list/find/record/approve/forget` 保留；SSH 必须使用原子的 `verify`，不能拆成外部 `find` 和 `record`。

## 3. SSH、shell 与会话

```js
createSshClient({ knownHosts, logger })
  connect(host, secret, {timeoutMs, signal})
    -> {client, fingerprint, keyType, hostKeyStatus, banner}
  exec(client, {command, sudoInput?, timeoutMs, signal, maxOutputBytes})
    -> {code, signal, output, truncated, timedOut, aborted}
buildCommand({command, cwd?, sudo?, sudoPassword?})
  -> {remoteCommand, sudoInput?: {prompt, password}}
remoteHome(client, {deadline?, timeoutMs?, signal?}) -> string
remoteStat(client, path, {deadline?, timeoutMs?, signal?}) -> stats | null
upload/download({client, localPath, remotePath, timeoutMs?, deadline?, signal?}) -> {bytes}
```

`sudoInput` 仅在 Host 内存中传递，不得作为工具参数、日志或返回值。`remoteCommand` 不包含密码。收到随机 sudo 认证提示才发送一次密码；缺密码、再次提示或取消时终止认证。缓存认证和 NOPASSWD 无提示时不发送密码。sudo 使用非登录 `bash -c`，不自动加载登录 profile；子命令 stdin 为 `/dev/null`，显式管道和重定向仍可用。

```js
openShell(client, {timeoutMs?, signal?}) -> ShellSession
  run(command, {timeoutMs, maxOutputBytes, signal?, sudoInput?, validate?}) -> RunOutcome
  close() -> Promise<void>
  alive: boolean
createSessionManager({ssh, config, logger})
  run({agentId,label,host,secret,command,cwd,sudo,sudoPassword,timeoutMs,maxOutputBytes,signal,validate?})
  list({agentId?}) / close(key) / closeHost(hostId) / closeAll() / dispose()
```

持久 shell 显式 `client.shell(false, ...)`，无 PTY；完整复合语句包裹命令并同时标记 stdout/stderr 结束。普通命令以当前 shell eval 执行、默认 stdin 为空，`cd/export` 状态保留；`cwd` 包装仍只影响本次调用。不能通过 read/cat 消费控制行。输出收集有界，控制帧分包与截断不混淆。

每个 `(agentId,label,hostId)` 共享进行中的创建任务并排队执行。实际执行前调用 `validate`，配置或凭据版本变化时禁止复用旧连接。取消排队任务不会取消别的活动任务；取消活动任务会关闭该会话，后续排队任务失败。空闲回收仅处理无活动、无排队任务的会话；容量满且无空闲会话时返回错误。关闭/卸载清理迟到连接，不自动重试可能有副作用的命令。

传输的绝对 deadline 覆盖连接、HOME 查询、SFTP、元数据、遍历和文件内容。下载校验目录项与目标包含关系，拒绝跟随目标子树符号链接，临时普通文件完成后原子替换目标；失败保留旧文件。远端目录链接不递归跟随。取消关闭客户端通道，不能保证已脱离 SSH 的远端进程终止或撤销已发生的操作。

## 4. 核心 service 与审批

```js
createService({config, paths, inventory, knownHosts, secrets, approval, logger})
  state() -> State
  saveHost(input + {secret?, clear?}) -> {host, state, warnings}
  deleteHost({id}) -> {removed, state, warnings}
  cleanupHost({id}) -> {state, warnings} // 只清理已退役凭据，不删除活动主机
  testHost({id?, draft?, secret?, clear?, signal?}) -> TestResult
  resolveTargets(targets) -> Host[]
  prepareRun({targets, command, cwd?, timeoutSec?, session?, sudo?, maxOutputBytes?}) -> plan
  run({plan, agentId?, signal?}) -> RunResult
  run({targets, command, ...options, agentId?, signal?}) -> RunResult // 内部直接调用便捷入口
  upload/download({targets, localPath, remotePath, timeoutSec?, signal?}) -> TransferResult
  listSessions({agentId?}) / closeSession({key}) / closeAllSessions()
  knownHostsState() / forgetKnownHost({host,port})
  approveFingerprint({host,port,fingerprint}) -> {entry,state}
  dispose() -> Promise<void>
```

工具先 `prepareRun`，按 plan 中的固定主机及有效 sudo 设置审批，再将同一 plan 交给 `run`。plan 单次使用，不含明文凭据；执行前检查配置 revision、凭据引用与信任版本。目标改变返回 `target-changed`，不重新展开分组、不自动执行新的目标。`sudo:false` 覆盖主机默认值，省略时才采用主机默认值。

`createApprovalGate({approval,mode}).check({...})` 的 modes：trusted 不请求审批；always 对全部命令请求；dangerous 对风险命中或实际提权请求。只有 `allowed-once` 放行；缺失服务或取消则拒绝。

保存、删除和清理串行提交，state 读取等待提交边界。卸载禁止新操作，取消网络操作并等待已开始的存储提交完成；凭据清理失败保留日志。主机或信任变化关闭相应旧会话。

TestResult 为 `{ok,target:{host,port},elapsedMs,hostKeyStatus,banner?,fingerprint?,keyType?,error?}`。编辑测试合并当前 draft、临时 secret 和 clear，但不保存这些输入；最新测试与配置版本不再匹配时失效。手动确认必须携带最近捕获的完全相同指纹，待确认有效期 5 分钟。

## 5. RPC 与公开结果

Client 使用 `ctx.connection.rpc.call('/api','remote-bash/rpc',{method,payload},signal)`。Host 注册鉴权载体下的 `/api/remote-bash/rpc` POST JSON 路由。当前 `fetch.register` 同步返回异步 disposer；实现兼容旧 Promise 返回，并等待早卸载清理。

信封：成功 `{ok:true,value}`，失败 `{ok:false,error:{code,message,details}}`。

| RPC method | payload | value |
|---|---|---|
| state | `{}` | State |
| host.save | 主机字段 + `secret?`, `clear?` | `{host,state,warnings}` |
| host.delete | `{id}` | `{removed,state,warnings}` |
| host.cleanup | `{id}` | `{state,warnings}` |
| host.test | `{id?,draft?,secret?,clear?}` | TestResult |
| knownHost.forget | `{host,port}` | `{removed,state}` |
| knownHost.approve | `{host,port,fingerprint}` | `{entry,state}` |
| session.close | `{key}` | `{closed,state}` |
| session.closeAll | `{}` | `{closed,state}` |

```js
State = {
  settings, credentialsAvailable,
  hosts: [{id,name,host,port,username,auth,keyPath,tags,note,sudo,createdAt,updatedAt,
    secret: {available,configured,fields:{password,passphrase,privateKey,sudoPassword}}}],
  groups: [{tag,hostIds}], knownHosts: [KnownHost], sessions: [SessionInfo],
  pendingCleanup: [{id,name}]
}
Warning = {code:'credential-cleanup-pending',message}
RunResult = {command,cwd,session,sudo,startedAt,durationMs,hosts:[{
  hostId,name,host,port,username,status:'ok'|'error'|'timeout',exitCode,signal,
  output,truncated,durationMs,error?,fingerprint?,keyType?,hostKeyStatus?,sessionKey?
}]}
TransferResult = {action:'upload'|'download',localPath,remotePath,durationMs,
  hosts:[{hostId,name,status:'ok'|'error',bytes,durationMs,localPath?,remotePath?,error?}]}
SessionInfo = {key,label,hostId,hostName,agentId,createdAt,lastUsedAt}
```

RunResult 的 sudo 表示本次目标中是否存在实际提权。每台主机独立报告结果，失败不会丢弃其他主机的成功结果。内部凭据引用不发送到页面。路径模板保留 `{host}/{name}/{id}/{basename}`；多主机下载按名称分文件或子目录。

## 6. 设置页与测试

设置页沿用 `settings.section` 槽、React.createElement、自有中英文文案与主题 token。变更请求统一排队，刷新代次在变更前后失效；所有状态入口拒绝过时响应。测试与信任绑定表单快照；待清理提示走 `host.cleanup` 重试，不调用删除。

`npm test` 发现全部 `tests/*.test.mjs`：原功能测试、存储/服务/SSH边界回归、实际客户端模块的组件逻辑测试和条件性 OpenSSH 测试。默认测试不依赖生产主机；OpenSSH/sudo 集成在 CI 隔离容器内显式启用，未启用时明确跳过。

CI 普通测试覆盖 Node 20 当前维护版本、22、24；独立 OpenSSH job 使用专用账户、合成凭据及 loopback 监听，无宿主端口发布。变更须通过 `npm test`、客户端与 Host JS 语法检查、`git diff --check`；真实浏览器或 OpenSSH 未执行时如实记录验证范围。
