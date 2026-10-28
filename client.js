/**
 * Remote Bash · Client 半（浏览器设置页）
 *
 * 契约（见 INTERFACE.md §6）：
 *  - window.__ModuleLoader__.load({ id, factory(require) })；id 必须等于包名；
 *  - factory 内只注册 settings.section 槽与 locale 字典，不碰宿主页面 DOM；
 *  - 通过 ctx.connection.rpc.call('/api', 'remote-bash/rpc', { method, payload }, signal)
 *    访问 Host，返回 { ok: true, value } / { ok: false, error } 信封；
 *  - 单文件、无构建步骤、只 require('react')，不 import 任何 Harness Client 包；
 *  - 所有可见文案走 ctx.locale 的自建 zh/en 字典；
 *  - 所有颜色/描边/背景只用 --dsw-alias-* 主题 token 的 inline style；
 *  - 弹窗自实现（遮罩 + 卡片、Escape、初始焦点、焦点陷阱、role=dialog + aria-modal），
 *    不写 document.body、不用 confirm()。
 *
 * 使用的 RPC 方法（Host 端 host/rpc.js 实现，INTERFACE.md §3）：
 *   state / host.save / host.delete / host.test /
 *   knownHost.forget / knownHost.approve /
 *   session.close / session.closeAll
 */
window.__ModuleLoader__.load({
  id: 'dsh-remote-bash',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    // ------------------------------------------------------------ 常量

    /** locale 命名空间。 */
    const NS = 'remote-bash'
    /** Host 注册的 RPC endpoint（完整 URL 为 /api/remote-bash/rpc）。 */
    const RPC_ENDPOINT = 'remote-bash/rpc'
    /** 凭据字段（与 INTERFACE.md §1/§2.4 一致），顺序即"清除"时的提交顺序。 */
    const SECRET_FIELDS = ['password', 'passphrase', 'privateKey', 'sudoPassword']
    /** 页面分段。 */
    const TABS = ['hosts', 'knownHosts', 'sessions']

    // ------------------------------------------------------------ 运行时绑定

    /** @type {null | ((method: string, payload?: unknown, signal?: AbortSignal) => Promise<unknown>)} */
    let rpcCall = null
    /** 当前语言的翻译函数，apply 时绑定。 */
    let translate = (key) => key
    /** locale 订阅函数，apply 时绑定。 */
    let subscribeLocale = () => () => {}

    /**
     * 调 Host RPC 并拆掉 connection 的响应信封。
     * 业务层只看到 value，或一个带 code/details 的 Error。
     * @param {string} method
     * @param {object} [payload]
     * @param {AbortSignal} [signal]
     */
    function call(method, payload, signal) {
      if (!rpcCall) {
        const failure = new Error('RPC unavailable')
        failure.code = 'rpc-unavailable'
        return Promise.reject(failure)
      }
      return rpcCall(method, payload ?? {}, signal).then((result) => {
        if (!result || typeof result.ok !== 'boolean') {
          const malformed = new Error('Unrecognized RPC response')
          malformed.code = 'bad-response'
          throw malformed
        }
        if (!result.ok) {
          const failure = result.error ?? {}
          const error = new Error(typeof failure.message === 'string' && failure.message ? failure.message : 'RPC failed')
          error.code = failure.code
          error.details = failure.details
          throw error
        }
        return result.value
      })
    }

    /** 订阅 locale 变化的渲染刷新（组件内使用，保证语言切换立即生效）。 */
    function useT(injected) {
      const [, force] = React.useReducer((value) => value + 1, 0)
      React.useEffect(() => subscribeLocale(force), [])
      return typeof injected === 'function' ? injected : translate
    }

    // ------------------------------------------------------------ 纯工具

    /** 极简占位符替换：{name}。 */
    function format(template, params) {
      return String(template ?? '').replace(/\{(\w+)\}/g, (match, key) => (
        params && key in params ? String(params[key]) : match
      ))
    }

    /** 逗号/顿号分隔的标签 -> 去重数组。 */
    function parseTags(input) {
      const seen = new Set()
      const output = []
      for (const part of String(input ?? '').split(/[,，、]/)) {
        const tag = part.trim()
        if (!tag) continue
        const lowered = tag.toLowerCase()
        if (seen.has(lowered)) continue
        seen.add(lowered)
        output.push(tag)
      }
      return output
    }

    /** epoch ms -> 本地时间；非法/空值显示"从未"。 */
    function timeText(value, t) {
      const stamp = Number(value)
      if (!Number.isFinite(stamp) || stamp <= 0) return t('common.never')
      try {
        return new Date(stamp).toLocaleString()
      } catch {
        return String(stamp)
      }
    }

    /** 合并 style 对象（忽略 falsy）。 */
    function mergeStyles(...styles) {
      return Object.assign({}, ...styles.filter(Boolean))
    }

    /** 把 Error 映射成可读文案；未知错误退回 message 或通用失败。 */
    const ERROR_KEYS = {
      'invalid-host': 'error.invalidHost',
      'duplicate-name': 'error.duplicateName',
      'host-key-changed': 'error.hostKeyChanged',
      'auth-failed': 'error.authFailed',
      'connect-timeout': 'error.connectTimeout',
      'connect-failed': 'error.connectFailed',
      aborted: 'error.aborted',
      'unknown-target': 'error.unknownTarget',
      'not-found': 'error.notFound',
      unavailable: 'error.unavailable',
      'rpc-unavailable': 'error.rpcUnavailable',
    }

    function describeError(t, error) {
      if (!error) return t('error.generic')
      const code = typeof error.code === 'string' ? error.code : ''
      const key = code ? ERROR_KEYS[code] : null
      const base = key ? t(key) : ''
      const message = typeof error.message === 'string' ? error.message.trim() : ''
      if (!base) return message || t('error.generic')
      if (message && message !== code && message !== base) return `${base} (${message})`
      return base
    }

    /** 主机行的 user@host:port。 */
    function hostAddress(host) {
      const user = host && host.username ? `${host.username}@` : ''
      return `${user}${host.host}:${host.port}`
    }

    // ------------------------------------------------------------ 文案

    /** 简体中文（键集与 en 严格一致）。 */
    const zh = {
      'settings.title': '远程命令',
      'page.title': '远程主机',
      'page.description': '用 SSH 在远程 Linux/macOS 主机上执行命令。密码与私钥保存在 DSH 凭据库，永不回传页面；首次连接自动记录主机指纹，之后指纹变化会被拒绝。',
      'common.refresh': '刷新',
      'common.refreshing': '刷新中…',
      'common.retry': '重试',
      'common.cancel': '取消',
      'common.save': '保存',
      'common.saving': '保存中…',
      'common.close': '关闭',
      'common.dismiss': '关闭提示',
      'common.add': '添加',
      'common.edit': '编辑',
      'common.delete': '删除',
      'common.clear': '清除',
      'common.undo': '撤销',
      'common.confirm': '确认',
      'common.loading': '加载中…',
      'common.never': '从未',
      'common.none': '无',
      'common.test': '测试连接',
      'common.testing': '测试中…',
      'common.unknown': '未知',
      'tabs.hosts': '主机',
      'tabs.knownHosts': '已知主机',
      'tabs.sessions': '会话',
      'state.loading': '正在加载远程命令状态…',
      'state.loadFailed': '无法读取远程命令状态。',
      'error.generic': '操作失败',
      'error.rpcUnavailable': '页面与后台的 RPC 通道未就绪，请确认插件已启用后刷新页面。',
      'error.invalidHost': '主机信息不完整或格式不正确。',
      'error.duplicateName': '主机名称已存在，请换一个。',
      'error.hostKeyChanged': '主机指纹与已记录的指纹不一致，连接已被拒绝。',
      'error.authFailed': '认证失败，请检查用户名与密码/私钥。',
      'error.connectTimeout': '连接超时。',
      'error.connectFailed': '无法连接到主机。',
      'error.aborted': '操作已取消。',
      'error.unknownTarget': '找不到目标主机。',
      'error.notFound': '找不到对应记录。',
      'error.unavailable': '所需的服务当前不可用。',
      'error.credentialsUnavailable': 'DSH 凭据服务不可用，无法保存密码/私钥。',
      'error.noPendingFingerprint': '没有待确认的新指纹，请先重新测试连接。',
      'error.fingerprintMismatch': '确认的指纹与最近一次连接看到的不一致，请重新测试连接。',
      'error.invalidSession': '会话 key 无效或会话已关闭。',
      'error.requiredFields': '请填写：{fields}',
      'error.invalidPort': '端口必须是 1–65535 的整数。',
      'credentials.unavailable': 'DSH 凭据库当前不可用：密码、私钥、口令与 sudo 密码将无法保存，已有凭据也无法读取。',
      'hosts.emptyTitle': '还没有远程主机',
      'hosts.emptyDesc': '添加一台主机后，Agent 就能通过 remote_bash 工具在它上面执行命令。',
      'hosts.add': '添加主机',
      'hosts.groupUntagged': '未分组',
      'hosts.authPassword': '密码认证',
      'hosts.authKey': '私钥认证',
      'hosts.sudo': 'sudo',
      'hosts.passwordSet': '密码已设置',
      'hosts.passwordUnset': '密码未设置',
      'hosts.keySet': '私钥已设置',
      'hosts.keyUnset': '私钥未设置',
      'hosts.passphraseSet': '口令已设置',
      'hosts.passphraseUnset': '口令未设置',
      'hosts.sudoPasswordSet': 'sudo 密码已设置',
      'hosts.sudoPasswordUnset': 'sudo 密码未设置',
      'hosts.test': '测试连接',
      'hosts.testing': '测试中…',
      'hosts.saved': '主机已保存',
      'hosts.deleted': '主机已删除',
      'hosts.deleteConfirm': '删除主机',
      'hosts.deleteConfirmDesc': '确定删除主机“{name}”？这会移除主机清单记录、凭据库中的密钥并关闭该主机的持久会话；已知主机指纹不会自动删除。',
      'test.successKnown': '连接成功，主机指纹与记录一致',
      'test.successNew': '连接成功，已自动记录主机指纹',
      'test.changed': '主机指纹发生变化，连接已拒绝',
      'test.failed': '连接失败',
      'test.elapsed': '耗时',
      'test.fingerprint': '指纹',
      'test.keyType': '密钥类型',
      'test.previousFingerprint': '之前的指纹',
      'test.banner': '服务端标识',
      'test.trust': '信任新指纹',
      'test.trusting': '正在信任…',
      'test.trusted': '已信任新指纹，可以重新测试连接。',
      'knownHosts.emptyTitle': '还没有已知主机',
      'knownHosts.emptyDesc': '首次成功连接某台主机后，它的指纹会自动出现在这里。',
      'knownHosts.fingerprint': '指纹',
      'knownHosts.keyType': '类型',
      'knownHosts.firstSeen': '首次记录',
      'knownHosts.lastSeen': '最近使用',
      'knownHosts.forget': '忘记',
      'knownHosts.forgetTitle': '忘记主机指纹',
      'knownHosts.forgetDesc': '确定忘记“{host}”的指纹？下次连接会重新走首次信任流程。',
      'knownHosts.forgotten': '已忘记该主机指纹',
      'sessions.emptyTitle': '还没有持久会话',
      'sessions.emptyDesc': '使用 session 参数执行命令后会创建持久 shell，cd、export 等状态会跨调用保留。',
      'sessions.idleHint': '持久会话空闲 {minutes} 分钟后会自动关闭。',
      'sessions.label': '会话',
      'sessions.host': '主机',
      'sessions.agent': 'Agent',
      'sessions.created': '创建',
      'sessions.lastUsed': '最近使用',
      'sessions.close': '关闭',
      'sessions.closeAll': '全部关闭',
      'sessions.closeTitle': '关闭持久会话',
      'sessions.closeDesc': '确定关闭会话“{label}”？会话内未保存的状态会丢失。',
      'sessions.closeAllTitle': '关闭全部持久会话',
      'sessions.closeAllDesc': '确定关闭全部 {n} 个持久会话？会话内未保存的状态会丢失。',
      'sessions.closed': '会话已关闭',
      'sessions.closedAll': '已关闭 {n} 个会话',
      'sessions.unknownAgent': '未知',
      'form.addTitle': '添加主机',
      'form.editTitle': '编辑主机',
      'form.sectionBasics': '连接信息',
      'form.sectionAuth': '认证与凭据',
      'form.sectionAdvanced': '其它',
      'form.name': '名称',
      'form.namePlaceholder': '例如 web-1',
      'form.host': '主机地址',
      'form.hostPlaceholder': 'IP 或域名，例如 10.0.0.5',
      'form.port': '端口',
      'form.username': '用户名',
      'form.usernamePlaceholder': '例如 deploy',
      'form.auth': '认证方式',
      'form.authPassword': '密码',
      'form.authKey': '私钥',
      'form.password': '登录密码',
      'form.passwordPlaceholder': '输入密码（留空则不修改）',
      'form.passwordConfigured': '已设置，留空不修改',
      'form.secretConfigured': '已设置',
      'form.keyPath': '私钥文件路径',
      'form.keyPathPlaceholder': '例如 ~/.ssh/id_ed25519',
      'form.keyPathHint': '留空时使用下方私钥内容或凭据库中已保存的私钥。',
      'form.privateKey': '私钥内容',
      'form.privateKeyPlaceholder': '粘贴 OpenSSH 私钥（留空则不修改）',
      'form.privateKeyConfigured': '已设置，留空不修改',
      'form.privateKeyHint': '私钥内容优先于文件路径；内容只写入 DSH 凭据库，不会回显。',
      'form.passphrase': '私钥口令',
      'form.passphrasePlaceholder': '输入口令（留空则不修改）',
      'form.passphraseConfigured': '已设置，留空不修改',
      'form.sudoPassword': 'sudo 密码',
      'form.sudoPasswordPlaceholder': '输入 sudo 密码（留空则不修改）',
      'form.sudoPasswordConfigured': '已设置，留空不修改',
      'form.sudoPasswordHint': '仅在启用 sudo 且远程用户需要密码时使用。',
      'form.tags': '分组标签',
      'form.tagsPlaceholder': '逗号分隔，例如 web, db',
      'form.tagsHint': '标签用于在对话里用 @标签 选择一批主机。',
      'form.note': '备注',
      'form.notePlaceholder': '可选说明',
      'form.sudoDefault': '默认使用 sudo',
      'form.sudoDefaultHint': '该主机上的命令默认通过 sudo 提权执行。',
      'form.clearPending': '保存时清除',
      'form.testHint': '可以用当前表单内容测试连接；首次连接会自动记录指纹。',
      'form.secretUnavailable': '凭据库不可用，以下密码类字段不可编辑。',
      'meta.dataDir': '数据目录',
      'meta.approval': '审批',
      'meta.timeout': '默认超时',
      'meta.parallel': '并发上限',
      'meta.idle': '会话空闲',
      'meta.minutes': '{minutes} 分钟',
      'meta.credentialsAvailable': '凭据库可用',
      'approval.dangerous': '危险命令',
      'approval.always': '每条命令',
      'approval.trusted': '不审批',
    }

    /** English (key set identical to zh). */
    const en = {
      'settings.title': 'Remote Bash',
      'page.title': 'Remote hosts',
      'page.description': 'Run commands on remote Linux/macOS hosts over SSH. Passwords and private keys live in the DSH credential store and are never sent back to this page; the first connection records the host fingerprint, and later changes are rejected.',
      'common.refresh': 'Refresh',
      'common.refreshing': 'Refreshing…',
      'common.retry': 'Retry',
      'common.cancel': 'Cancel',
      'common.save': 'Save',
      'common.saving': 'Saving…',
      'common.close': 'Close',
      'common.dismiss': 'Dismiss',
      'common.add': 'Add',
      'common.edit': 'Edit',
      'common.delete': 'Delete',
      'common.clear': 'Clear',
      'common.undo': 'Undo',
      'common.confirm': 'Confirm',
      'common.loading': 'Loading…',
      'common.never': 'Never',
      'common.none': 'None',
      'common.test': 'Test connection',
      'common.testing': 'Testing…',
      'common.unknown': 'Unknown',
      'tabs.hosts': 'Hosts',
      'tabs.knownHosts': 'Known hosts',
      'tabs.sessions': 'Sessions',
      'state.loading': 'Loading Remote Bash state…',
      'state.loadFailed': 'Could not read the Remote Bash state.',
      'error.generic': 'Operation failed',
      'error.rpcUnavailable': 'The page-to-Host RPC channel is not ready. Make sure the plugin is enabled, then refresh the page.',
      'error.invalidHost': 'The host details are incomplete or invalid.',
      'error.duplicateName': 'A host with this name already exists.',
      'error.hostKeyChanged': 'The host fingerprint differs from the recorded one, so the connection was rejected.',
      'error.authFailed': 'Authentication failed. Check the username and password/private key.',
      'error.connectTimeout': 'Connection timed out.',
      'error.connectFailed': 'Could not connect to the host.',
      'error.aborted': 'The operation was cancelled.',
      'error.unknownTarget': 'No matching target host.',
      'error.notFound': 'The record was not found.',
      'error.unavailable': 'A required service is unavailable.',
      'error.credentialsUnavailable': 'The DSH credential service is unavailable, so passwords/keys cannot be saved.',
      'error.noPendingFingerprint': 'There is no pending new fingerprint. Test the connection again first.',
      'error.fingerprintMismatch': 'The fingerprint does not match the one seen by the latest test; test the connection again.',
      'error.invalidSession': 'The session key is invalid or the session is already closed.',
      'error.requiredFields': 'Fill in: {fields}',
      'error.invalidPort': 'The port must be an integer between 1 and 65535.',
      'credentials.unavailable': 'The DSH credential store is unavailable: passwords, private keys, passphrases and sudo passwords cannot be saved, and existing credentials cannot be read.',
      'hosts.emptyTitle': 'No remote hosts yet',
      'hosts.emptyDesc': 'Add a host and the Agent can run commands on it through the remote_bash tool.',
      'hosts.add': 'Add host',
      'hosts.groupUntagged': 'Ungrouped',
      'hosts.authPassword': 'Password',
      'hosts.authKey': 'Private key',
      'hosts.sudo': 'sudo',
      'hosts.passwordSet': 'Password set',
      'hosts.passwordUnset': 'No password',
      'hosts.keySet': 'Key set',
      'hosts.keyUnset': 'No key',
      'hosts.passphraseSet': 'Passphrase set',
      'hosts.passphraseUnset': 'No passphrase',
      'hosts.sudoPasswordSet': 'sudo password set',
      'hosts.sudoPasswordUnset': 'No sudo password',
      'hosts.test': 'Test connection',
      'hosts.testing': 'Testing…',
      'hosts.saved': 'Host saved',
      'hosts.deleted': 'Host deleted',
      'hosts.deleteConfirm': 'Delete host',
      'hosts.deleteConfirmDesc': 'Delete host “{name}”? This removes the inventory record, deletes its stored credentials, and closes its persistent sessions; the known-host fingerprint is kept.',
      'test.successKnown': 'Connected; the host fingerprint matches the record',
      'test.successNew': 'Connected; the host fingerprint was recorded automatically',
      'test.changed': 'The host fingerprint changed, so the connection was rejected',
      'test.failed': 'Connection failed',
      'test.elapsed': 'Elapsed',
      'test.fingerprint': 'Fingerprint',
      'test.keyType': 'Key type',
      'test.previousFingerprint': 'Previous fingerprint',
      'test.banner': 'Server banner',
      'test.trust': 'Trust new fingerprint',
      'test.trusting': 'Trusting…',
      'test.trusted': 'The new fingerprint was trusted. Test the connection again.',
      'knownHosts.emptyTitle': 'No known hosts yet',
      'knownHosts.emptyDesc': 'After a host connects successfully for the first time, its fingerprint appears here.',
      'knownHosts.fingerprint': 'Fingerprint',
      'knownHosts.keyType': 'Type',
      'knownHosts.firstSeen': 'First seen',
      'knownHosts.lastSeen': 'Last used',
      'knownHosts.forget': 'Forget',
      'knownHosts.forgetTitle': 'Forget host fingerprint',
      'knownHosts.forgetDesc': 'Forget the fingerprint of “{host}”? The next connection will go through the first-trust flow again.',
      'knownHosts.forgotten': 'Host fingerprint forgotten',
      'sessions.emptyTitle': 'No persistent sessions',
      'sessions.emptyDesc': 'Running a command with the session option opens a persistent shell so cd and export survive across calls.',
      'sessions.idleHint': 'Persistent sessions close automatically after {minutes} minutes of inactivity.',
      'sessions.label': 'Session',
      'sessions.host': 'Host',
      'sessions.agent': 'Agent',
      'sessions.created': 'Created',
      'sessions.lastUsed': 'Last used',
      'sessions.close': 'Close',
      'sessions.closeAll': 'Close all',
      'sessions.closeTitle': 'Close persistent session',
      'sessions.closeDesc': 'Close session “{label}”? Unsaved state in the session is lost.',
      'sessions.closeAllTitle': 'Close all persistent sessions',
      'sessions.closeAllDesc': 'Close all {n} persistent sessions? Unsaved state in them is lost.',
      'sessions.closed': 'Session closed',
      'sessions.closedAll': 'Closed {n} sessions',
      'sessions.unknownAgent': 'Unknown',
      'form.addTitle': 'Add host',
      'form.editTitle': 'Edit host',
      'form.sectionBasics': 'Connection',
      'form.sectionAuth': 'Authentication & credentials',
      'form.sectionAdvanced': 'Other',
      'form.name': 'Name',
      'form.namePlaceholder': 'e.g. web-1',
      'form.host': 'Host address',
      'form.hostPlaceholder': 'IP or domain, e.g. 10.0.0.5',
      'form.port': 'Port',
      'form.username': 'Username',
      'form.usernamePlaceholder': 'e.g. deploy',
      'form.auth': 'Authentication',
      'form.authPassword': 'Password',
      'form.authKey': 'Private key',
      'form.password': 'Login password',
      'form.passwordPlaceholder': 'Enter a password (leave blank to keep)',
      'form.passwordConfigured': 'Set — leave blank to keep',
      'form.secretConfigured': 'Set',
      'form.keyPath': 'Private key path',
      'form.keyPathPlaceholder': 'e.g. ~/.ssh/id_ed25519',
      'form.keyPathHint': 'When empty, the key content below or the private key already in the credential store is used.',
      'form.privateKey': 'Private key content',
      'form.privateKeyPlaceholder': 'Paste an OpenSSH private key (leave blank to keep)',
      'form.privateKeyConfigured': 'Set — leave blank to keep',
      'form.privateKeyHint': 'Key content takes precedence over the file path; it is written to the DSH credential store only and is never echoed back.',
      'form.passphrase': 'Key passphrase',
      'form.passphrasePlaceholder': 'Enter a passphrase (leave blank to keep)',
      'form.passphraseConfigured': 'Set — leave blank to keep',
      'form.sudoPassword': 'sudo password',
      'form.sudoPasswordPlaceholder': 'Enter the sudo password (leave blank to keep)',
      'form.sudoPasswordConfigured': 'Set — leave blank to keep',
      'form.sudoPasswordHint': 'Only used when sudo is enabled and the remote user needs a password.',
      'form.tags': 'Group tags',
      'form.tagsPlaceholder': 'Comma separated, e.g. web, db',
      'form.tagsHint': 'Tags select a set of hosts with @tag in conversations.',
      'form.note': 'Note',
      'form.notePlaceholder': 'Optional description',
      'form.sudoDefault': 'Use sudo by default',
      'form.sudoDefaultHint': 'Commands on this host are elevated with sudo by default.',
      'form.clearPending': 'Cleared on save',
      'form.testHint': 'You can test the current form contents; the first connection records the fingerprint automatically.',
      'form.secretUnavailable': 'The credential store is unavailable, so the password fields below cannot be edited.',
      'meta.dataDir': 'Data directory',
      'meta.approval': 'Approval',
      'meta.timeout': 'Default timeout',
      'meta.parallel': 'Parallel limit',
      'meta.idle': 'Session idle',
      'meta.minutes': '{minutes} min',
      'meta.credentialsAvailable': 'Credential store available',
      'approval.dangerous': 'Dangerous commands',
      'approval.always': 'Every command',
      'approval.trusted': 'Never',
    }

    // ------------------------------------------------------------ 主题 token
    // 只用 --dsw-alias-* token（颜色/描边/背景/阴影），几何尺寸与字体用普通数值。

    const C = {
      labelPrimary: 'var(--dsw-alias-label-primary)',
      labelSecondary: 'var(--dsw-alias-label-secondary)',
      labelTertiary: 'var(--dsw-alias-label-tertiary)',
      caption: 'var(--dsw-alias-label-caption)',
      onPrimary: 'var(--dsw-alias-label-primary-foreground)',
      borderL1: 'var(--dsw-alias-border-l1)',
      borderL2: 'var(--dsw-alias-border-l2)',
      layer1: 'var(--dsw-alias-bg-layer-1)',
      layer2: 'var(--dsw-alias-bg-layer-2)',
      cardFill: 'var(--dsw-alias-settings-card-fill)',
      cardStroke: 'var(--dsw-alias-settings-card-stroke)',
      brand: 'var(--dsw-alias-brand-primary-new-colorprimary-new-color)',
      brandPrimary: 'var(--dsw-alias-brand-primary)',
      primaryFill: 'var(--dsw-alias-button-primary-fill)',
      primaryHover: 'var(--dsw-alias-button-primary-hover)',
      hover: 'var(--dsw-alias-interactive-bg-hover)',
      hoverSolid: 'var(--dsw-alias-interactive-bg-hover-solid)',
      mask: 'var(--dsw-alias-bg-mask-1)',
      error: 'var(--dsw-alias-state-error-primary)',
      warn: 'var(--dsw-alias-state-warn-primary)',
      success: 'var(--dsw-alias-state-success-primary)',
      idle: 'var(--dsw-alias-state-idle-primary)',
      switchThumb: 'var(--dsw-alias-switch-thumb)',
    }

    const MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace'

    /** 浅色底的品牌色淡背景。 */
    function tint(color, percent) {
      return `color-mix(in srgb, ${color} ${percent}%, transparent)`
    }

    const TONE_COLOR = {
      info: C.brand,
      success: C.success,
      warn: C.warn,
      error: C.error,
    }

    /** 布局与外观（inline style，无 <style> 注入）。 */
    const S = {
      root: {
        display: 'flex',
        flexDirection: 'column',
        gap: 14,
        width: '100%',
        minWidth: 0,
        color: C.labelPrimary,
        fontSize: 13,
        lineHeight: '20px',
      },
      header: {
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        gap: 16,
        flexWrap: 'wrap',
      },
      headerText: { display: 'flex', flexDirection: 'column', gap: 2, minWidth: 240, flex: '1 1 320px' },
      h1: { margin: 0, fontSize: 16, lineHeight: '24px', fontWeight: 600, color: C.labelPrimary },
      desc: { margin: 0, fontSize: 12, lineHeight: '18px', color: C.labelSecondary, maxWidth: 720 },
      actions: { display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 },
      tabs: {
        display: 'flex',
        gap: 2,
        padding: 2,
        borderRadius: 8,
        background: C.layer2,
        alignSelf: 'flex-start',
        border: `1px solid ${C.borderL1}`,
      },
      tab: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '4px 12px',
        border: '1px solid transparent',
        borderRadius: 6,
        background: 'transparent',
        color: C.labelSecondary,
        font: 'inherit',
        fontSize: 12,
        lineHeight: '18px',
        cursor: 'pointer',
      },
      tabActive: {
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '4px 12px',
        border: `1px solid ${C.cardStroke}`,
        borderRadius: 6,
        background: C.layer1,
        color: C.labelPrimary,
        font: 'inherit',
        fontSize: 12,
        lineHeight: '18px',
        cursor: 'pointer',
        fontWeight: 500,
      },
      tabHover: { color: C.labelPrimary, background: C.hover },
      tabCount: {
        minWidth: 16,
        padding: '0 5px',
        borderRadius: 999,
        background: tint(C.labelPrimary, 7),
        color: C.labelSecondary,
        fontSize: 10,
        lineHeight: '16px',
        textAlign: 'center',
        fontWeight: 500,
      },
      tabPanel: { display: 'flex', flexDirection: 'column', gap: 12, minWidth: 0 },
      centerState: {
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 10,
        padding: '40px 16px',
        border: `1px dashed ${C.borderL2}`,
        borderRadius: 10,
        color: C.labelSecondary,
        fontSize: 13,
        textAlign: 'center',
      },
      empty: {
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 4,
        padding: '36px 20px',
        border: `1px dashed ${C.borderL2}`,
        borderRadius: 10,
        textAlign: 'center',
      },
      emptyTitle: { fontSize: 14, fontWeight: 600, color: C.labelPrimary },
      emptyDesc: { fontSize: 12, lineHeight: '18px', color: C.labelSecondary, maxWidth: 520 },
      list: {
        display: 'flex',
        flexDirection: 'column',
        border: `1px solid ${C.cardStroke}`,
        borderRadius: 10,
        background: C.cardFill,
        overflow: 'hidden',
      },
      listRow: { display: 'flex', flexWrap: 'wrap', alignItems: 'flex-start', gap: 12, padding: '12px 14px' },
      listRowDivided: { borderTop: `1px solid ${C.borderL1}` },
      rowMain: { display: 'flex', flexDirection: 'column', gap: 4, flex: 1, minWidth: 0 },
      rowTitleLine: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', minWidth: 0 },
      rowTitle: {
        fontSize: 13,
        fontWeight: 600,
        color: C.labelPrimary,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        maxWidth: '100%',
      },
      rowSub: { fontSize: 12, lineHeight: '18px', color: C.labelSecondary, fontFamily: MONO, wordBreak: 'break-all' },
      chipRow: { display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginTop: 2 },
      rowActions: { display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0, flexWrap: 'wrap', justifyContent: 'flex-end' },
      groupHead: { display: 'flex', alignItems: 'center', gap: 8, margin: '4px 0 2px' },
      groupTitle: {
        fontSize: 12,
        fontWeight: 600,
        color: C.labelSecondary,
        letterSpacing: '0.02em',
      },
      groupCount: { fontSize: 11, color: C.labelTertiary },
      btn: {
        boxSizing: 'border-box',
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
        minHeight: 30,
        padding: '4px 12px',
        border: `1px solid ${C.borderL2}`,
        borderRadius: 7,
        background: C.layer1,
        color: C.labelPrimary,
        font: 'inherit',
        fontSize: 12,
        lineHeight: '18px',
        cursor: 'pointer',
        whiteSpace: 'nowrap',
      },
      btnHover: { background: C.hover },
      btnPrimary: {
        boxSizing: 'border-box',
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
        minHeight: 30,
        padding: '4px 12px',
        border: `1px solid ${C.primaryFill}`,
        borderRadius: 7,
        background: C.primaryFill,
        color: C.onPrimary,
        font: 'inherit',
        fontSize: 12,
        lineHeight: '18px',
        cursor: 'pointer',
        whiteSpace: 'nowrap',
        fontWeight: 500,
      },
      btnPrimaryHover: { background: C.primaryHover, borderColor: C.primaryHover },
      btnDanger: {
        boxSizing: 'border-box',
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
        minHeight: 30,
        padding: '4px 12px',
        border: `1px solid ${tint(C.error, 45)}`,
        borderRadius: 7,
        background: 'transparent',
        color: C.error,
        font: 'inherit',
        fontSize: 12,
        lineHeight: '18px',
        cursor: 'pointer',
        whiteSpace: 'nowrap',
      },
      btnDangerHover: { background: tint(C.error, 10), borderColor: tint(C.error, 60) },
      btnDangerSolid: {
        boxSizing: 'border-box',
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
        minHeight: 30,
        padding: '4px 12px',
        border: `1px solid ${C.error}`,
        borderRadius: 7,
        background: C.error,
        color: C.onPrimary,
        font: 'inherit',
        fontSize: 12,
        lineHeight: '18px',
        cursor: 'pointer',
        whiteSpace: 'nowrap',
        fontWeight: 500,
      },
      btnDangerSolidHover: { filter: 'brightness(0.92)' },
      btnGhost: {
        boxSizing: 'border-box',
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 6,
        minHeight: 30,
        padding: '4px 10px',
        border: '1px solid transparent',
        borderRadius: 7,
        background: 'transparent',
        color: C.labelSecondary,
        font: 'inherit',
        fontSize: 12,
        lineHeight: '18px',
        cursor: 'pointer',
        whiteSpace: 'nowrap',
      },
      btnGhostHover: { background: C.hover, color: C.labelPrimary },
      btnSmall: { minHeight: 24, padding: '2px 8px', fontSize: 11, lineHeight: '16px' },
      btnDisabled: { opacity: 0.5, cursor: 'not-allowed' },
      focusRing: { outline: `2px solid ${C.brand}`, outlineOffset: 1 },
      field: { display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 },
      fieldLabel: { display: 'inline-flex', alignItems: 'center', gap: 2, fontSize: 12, lineHeight: '18px', color: C.labelSecondary, fontWeight: 500 },
      fieldHint: { fontSize: 11, lineHeight: '16px', color: C.labelTertiary },
      input: {
        boxSizing: 'border-box',
        width: '100%',
        minHeight: 30,
        padding: '5px 9px',
        border: `1px solid ${C.borderL2}`,
        borderRadius: 7,
        background: C.layer1,
        color: C.labelPrimary,
        font: 'inherit',
        fontSize: 12,
        lineHeight: '18px',
        outline: 'none',
      },
      inputFocus: { borderColor: C.brand, boxShadow: `0 0 0 2px ${tint(C.brand, 25)}` },
      inputDisabled: { opacity: 0.55, cursor: 'not-allowed' },
      textarea: {
        boxSizing: 'border-box',
        width: '100%',
        minHeight: 76,
        padding: '6px 9px',
        border: `1px solid ${C.borderL2}`,
        borderRadius: 7,
        background: C.layer1,
        color: C.labelPrimary,
        fontFamily: MONO,
        fontSize: 12,
        lineHeight: '18px',
        resize: 'vertical',
        outline: 'none',
      },
      labelRow: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' },
      linkBtn: {
        border: 'none',
        background: 'transparent',
        padding: 0,
        color: C.brand,
        font: 'inherit',
        fontSize: 12,
        lineHeight: '18px',
        cursor: 'pointer',
        textDecoration: 'underline',
        textUnderlineOffset: 2,
      },
      iconBtn: {
        boxSizing: 'border-box',
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: 26,
        height: 26,
        padding: 0,
        border: '1px solid transparent',
        borderRadius: 6,
        background: 'transparent',
        color: C.labelSecondary,
        font: 'inherit',
        fontSize: 13,
        lineHeight: '20px',
        cursor: 'pointer',
        flexShrink: 0,
      },
      iconBtnHover: { background: C.hover, color: C.labelPrimary },
      modalOverlay: {
        position: 'fixed',
        top: 0,
        right: 0,
        bottom: 0,
        left: 0,
        zIndex: 1000,
        display: 'grid',
        placeItems: 'center',
        padding: 24,
        background: C.mask,
      },
      modalCard: {
        display: 'flex',
        flexDirection: 'column',
        width: 'min(620px, 100%)',
        maxHeight: 'min(760px, calc(100vh - 48px))',
        borderRadius: 12,
        border: `1px solid ${C.borderL2}`,
        background: C.layer2,
        color: C.labelPrimary,
        boxShadow: '0 18px 48px var(--dsw-alias-bg-mask-1)',
        overflow: 'hidden',
        outline: 'none',
      },
      modalHead: {
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 12,
        padding: '12px 16px',
        borderBottom: `1px solid ${C.borderL1}`,
        flex: 'none',
      },
      modalTitle: { margin: 0, fontSize: 14, lineHeight: '22px', fontWeight: 600, color: C.labelPrimary },
      modalBody: { padding: '14px 16px', overflowY: 'auto', flex: '1 1 auto', minHeight: 0 },
      modalFoot: {
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
        padding: '10px 16px 12px',
        borderTop: `1px solid ${C.borderL1}`,
        flex: 'none',
      },
      modalActions: { display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8, flexWrap: 'wrap' },
      modalText: { margin: '0 0 8px', fontSize: 13, lineHeight: '20px', color: C.labelPrimary, wordBreak: 'break-word' },
      formBody: { display: 'flex', flexDirection: 'column', gap: 14 },
      formGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 12 },
      formSection: { display: 'flex', flexDirection: 'column', gap: 12, borderTop: `1px solid ${C.borderL1}`, paddingTop: 14 },
      formSectionTitle: { fontSize: 12, lineHeight: '18px', fontWeight: 600, color: C.labelSecondary },
      testBox: {
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        padding: '10px 12px',
        border: `1px solid ${C.borderL1}`,
        borderRadius: 8,
        background: tint(C.labelPrimary, 3),
        fontSize: 12,
        lineHeight: '18px',
      },
      detailList: { display: 'flex', flexDirection: 'column', gap: 2 },
      detailRow: { display: 'flex', alignItems: 'flex-start', gap: 8, minWidth: 0 },
      detailLabel: { flex: '0 0 104px', color: C.labelSecondary, fontSize: 11, lineHeight: '18px' },
      detailValue: { flex: '1 1 auto', minWidth: 0, color: C.labelPrimary, fontFamily: MONO, fontSize: 11, lineHeight: '18px', wordBreak: 'break-all' },
      detailValueWide: { flex: '1 1 auto', minWidth: 0, color: C.labelSecondary, fontSize: 11, lineHeight: '18px', wordBreak: 'break-word' },
      metaBox: {
        display: 'flex',
        flexDirection: 'column',
        gap: 4,
        paddingTop: 10,
        borderTop: `1px solid ${C.borderL1}`,
        fontSize: 11,
        lineHeight: '17px',
        color: C.labelTertiary,
      },
      metaRow: { display: 'flex', flexWrap: 'wrap', gap: '2px 6px', alignItems: 'baseline' },
      metaMono: { fontFamily: MONO, wordBreak: 'break-all' },
      sessionMain: { display: 'flex', flexDirection: 'column', gap: 3, flex: 1, minWidth: 0 },
      sessionTitleLine: { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', minWidth: 0 },
      sessionTitle: { fontSize: 13, fontWeight: 600, color: C.labelPrimary, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
      monoTruncate: {
        display: 'inline-block',
        maxWidth: 220,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        verticalAlign: 'bottom',
        fontFamily: MONO,
      },
      hintLine: { fontSize: 11, lineHeight: '17px', color: C.labelTertiary },
    }

    // ------------------------------------------------------------ 基础组件

    /** 按钮当前的 hover / focus 状态。 */
    function useInteractive() {
      const [hover, setHover] = React.useState(false)
      const [focus, setFocus] = React.useState(false)
      return {
        hover,
        focus,
        handlers: {
          onMouseEnter: () => setHover(true),
          onMouseLeave: () => setHover(false),
          onFocus: () => setFocus(true),
          onBlur: () => setFocus(false),
        },
      }
    }

    /**
     * 按钮。variant: default | primary | danger | dangerSolid | ghost。
     * busy 时仅禁用并保留文案（调用方给"保存中…"之类的文案）。
     */
    function Btn(props) {
      const { variant = 'default', small, disabled, busy, onClick, type, title, style, autofocus, children } = props
      const state = useInteractive()
      const base = variant === 'primary'
        ? S.btnPrimary
        : variant === 'danger'
          ? S.btnDanger
          : variant === 'dangerSolid'
            ? S.btnDangerSolid
            : variant === 'ghost'
              ? S.btnGhost
              : S.btn
      const hoverStyle = variant === 'primary'
        ? S.btnPrimaryHover
        : variant === 'danger'
          ? S.btnDangerHover
          : variant === 'dangerSolid'
            ? S.btnDangerSolidHover
            : variant === 'ghost'
              ? S.btnGhostHover
              : S.btnHover
      const isDisabled = Boolean(disabled || busy)
      return h('button', mergeStyles(
        {
          type: type ?? 'button',
          onClick: isDisabled ? undefined : onClick,
          disabled: isDisabled,
          title,
          'data-modal-autofocus': autofocus ? '' : undefined,
          'aria-busy': busy ? 'true' : undefined,
        },
        state.handlers,
        { style: mergeStyles(base, small && S.btnSmall, state.hover && !isDisabled && hoverStyle, state.focus && !isDisabled && S.focusRing, isDisabled && S.btnDisabled, style) },
      ), children)
    }

    /** 不可交互的圆角标签。tone: neutral | muted | success | warn | error | brand。 */
    function Chip(props) {
      const { tone = 'neutral', mono, title, children } = props
      const map = {
        neutral: { color: C.labelSecondary, background: tint(C.labelPrimary, 6), border: C.borderL1 },
        muted: { color: C.labelTertiary, background: 'transparent', border: C.borderL1 },
        success: { color: C.labelPrimary, background: tint(C.success, 14), border: tint(C.success, 35) },
        warn: { color: C.labelPrimary, background: tint(C.warn, 16), border: tint(C.warn, 40) },
        error: { color: C.error, background: tint(C.error, 9), border: tint(C.error, 35) },
        brand: { color: C.brand, background: tint(C.brand, 9), border: tint(C.brand, 30) },
      }
      const toneStyle = map[tone] || map.neutral
      return h('span', {
        title,
        style: {
          display: 'inline-flex',
          alignItems: 'center',
          gap: 4,
          padding: '1px 7px',
          borderRadius: 999,
          fontSize: 10,
          lineHeight: '16px',
          whiteSpace: 'nowrap',
          border: `1px solid ${toneStyle.border}`,
          color: toneStyle.color,
          background: toneStyle.background,
          fontFamily: mono ? MONO : 'inherit',
        },
      }, children)
    }

    /** 顶部提示条。tone: info | success | warn | error。 */
    function Banner(props) {
      const { t, tone = 'info', action, onDismiss, children } = props
      const color = TONE_COLOR[tone] || TONE_COLOR.info
      return h('div', {
        role: tone === 'error' || tone === 'warn' ? 'alert' : 'status',
        style: {
          display: 'flex',
          alignItems: 'flex-start',
          gap: 8,
          padding: '7px 10px 7px 12px',
          border: `1px solid ${tint(color, 34)}`,
          borderRadius: 8,
          background: tint(color, 8),
          color: C.labelPrimary,
          fontSize: 12,
          lineHeight: '18px',
        },
      },
      h('span', {
        'aria-hidden': 'true',
        style: { flex: 'none', width: 7, height: 7, marginTop: 5, borderRadius: '50%', background: color },
      }),
      h('div', { style: { flex: '1 1 auto', minWidth: 0, wordBreak: 'break-word' } }, children),
      action || null,
      onDismiss
        ? h('button', {
          type: 'button',
          onClick: onDismiss,
          'aria-label': t('common.dismiss'),
          title: t('common.dismiss'),
          style: { flex: 'none', border: 'none', background: 'transparent', color: C.labelSecondary, font: 'inherit', fontSize: 12, lineHeight: '18px', cursor: 'pointer', padding: '0 2px' },
        }, '✕')
        : null)
    }

    /** 输入框。 */
    function TextInput(props) {
      const { id, value, placeholder, type, disabled, autoComplete, onChange, style, ariaLabel, autoFocus } = props
      const state = useInteractive()
      return h('input', mergeStyles(
        {
          id,
          type: type || 'text',
          value: value ?? '',
          placeholder,
          disabled,
          autoComplete: autoComplete || 'off',
          spellCheck: false,
          'aria-label': ariaLabel,
          'data-modal-autofocus': autoFocus ? '' : undefined,
          onChange: (event) => onChange?.(event.target.value),
        },
        state.handlers,
        { style: mergeStyles(S.input, state.focus && !disabled && S.inputFocus, disabled && S.inputDisabled, style) },
      ))
    }

    /** 多行文本。 */
    function TextArea(props) {
      const { id, value, placeholder, rows, disabled, mono, onChange, style, ariaLabel } = props
      const state = useInteractive()
      return h('textarea', mergeStyles(
        {
          id,
          value: value ?? '',
          placeholder,
          rows: rows ?? 3,
          disabled,
          spellCheck: false,
          'aria-label': ariaLabel,
          onChange: (event) => onChange?.(event.target.value),
        },
        state.handlers,
        {
          style: mergeStyles(
            S.textarea,
            !mono && { fontFamily: 'inherit' },
            state.focus && !disabled && S.inputFocus,
            disabled && S.inputDisabled,
            style,
          ),
        },
      ))
    }

    /** 单选组（认证方式）。 */
    function RadioGroup(props) {
      const { name, label, value, options, disabled, onChange } = props
      return h('div', {
        role: 'radiogroup',
        'aria-label': label,
        style: { display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap', minHeight: 30 },
      }, options.map((option) => {
        const id = `${name}-${option.value}`
        return h('label', {
          key: option.value,
          htmlFor: id,
          style: {
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            fontSize: 12,
            lineHeight: '18px',
            color: disabled ? C.labelTertiary : C.labelPrimary,
            cursor: disabled ? 'not-allowed' : 'pointer',
          },
        },
        h('input', {
          id,
          type: 'radio',
          name,
          value: option.value,
          checked: value === option.value,
          disabled,
          onChange: () => onChange?.(option.value),
          style: { margin: 0, accentColor: C.brand },
        }),
        option.label)
      }))
    }

    /** 开关（默认 sudo）。 */
    function Switch(props) {
      const { label, checked, disabled, onChange } = props
      const state = useInteractive()
      const track = {
        position: 'relative',
        width: 34,
        height: 20,
        flex: 'none',
        padding: 0,
        border: 'none',
        borderRadius: 999,
        background: checked ? C.brand : C.idle,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        transition: 'background-color 120ms ease',
      }
      const thumb = {
        position: 'absolute',
        top: 3,
        left: checked ? 17 : 3,
        width: 14,
        height: 14,
        borderRadius: '50%',
        background: C.switchThumb,
        transition: 'left 120ms ease',
      }
      return h('div', { style: { display: 'flex', alignItems: 'center', gap: 8 } },
        h('button', mergeStyles(
          {
            type: 'button',
            role: 'switch',
            'aria-checked': checked ? 'true' : 'false',
            'aria-label': label,
            disabled,
            onClick: disabled ? undefined : () => onChange?.(!checked),
          },
          state.handlers,
          { style: mergeStyles(track, state.focus && !disabled && S.focusRing) },
        ), h('span', { 'aria-hidden': 'true', style: thumb })),
        label ? h('span', { style: { fontSize: 12, lineHeight: '18px', color: disabled ? C.labelTertiary : C.labelPrimary } }, label) : null)
    }

    /** 字段容器；给了 htmlFor 时用 <label>，否则用普通文本标签。 */
    function Field(props) {
      const { label, hint, required, htmlFor, children, style } = props
      const labelContent = label
        ? h(React.Fragment, null,
          label,
          required ? h('span', { 'aria-hidden': 'true', style: { color: C.error } }, '*') : null)
        : null
      return h('div', { style: mergeStyles(S.field, style) },
        labelContent
          ? (htmlFor
            ? h('label', { htmlFor, style: S.fieldLabel }, labelContent)
            : h('div', { style: S.fieldLabel }, labelContent))
          : null,
        children,
        hint ? h('div', { style: S.fieldHint }, hint) : null)
    }

    /** 分段标签页。 */
    function Tabs(props) {
      const { t, items, value, onChange } = props
      return h('div', {
        role: 'tablist',
        'aria-label': t('page.title'),
        style: S.tabs,
      }, items.map((item, index) => h(TabButton, {
        key: item.id,
        item,
        index,
        items,
        selected: item.id === value,
        onSelect: onChange,
      })))
    }

    function TabButton(props) {
      const { item, index, items, selected, onSelect } = props
      const state = useInteractive()
      const base = selected ? S.tabActive : S.tab
      return h('button', mergeStyles(
        {
          type: 'button',
          role: 'tab',
          id: `remote-bash-tab-${item.id}`,
          'aria-selected': selected ? 'true' : 'false',
          'aria-controls': `remote-bash-panel-${item.id}`,
          tabIndex: selected ? 0 : -1,
          onClick: () => onSelect(item.id),
          onKeyDown: (event) => {
            if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return
            event.preventDefault()
            const delta = event.key === 'ArrowRight' ? 1 : -1
            const next = items[(index + delta + items.length) % items.length]
            onSelect(next.id)
            if (typeof document !== 'undefined') {
              const node = document.getElementById(`remote-bash-tab-${next.id}`)
              if (node && typeof node.focus === 'function') node.focus()
            }
          },
        },
        state.handlers,
        { style: mergeStyles(base, state.hover && !selected && S.tabHover, state.focus && S.focusRing) },
      ),
      item.label,
      item.count !== undefined ? h('span', { style: S.tabCount }, String(item.count)) : null)
    }

    /**
     * 自实现可访问弹窗：遮罩 + 卡片、Escape 关闭、初始焦点、Tab 焦点陷阱、
     * role=dialog + aria-modal + aria-labelledby。不写 document.body。
     */
    function Modal(props) {
      const { t, title, onClose, children, footer } = props
      const titleId = React.useId()
      const cardRef = React.useRef(null)
      const onCloseRef = React.useRef(onClose)
      onCloseRef.current = onClose

      React.useEffect(() => {
        if (typeof document === 'undefined') return undefined
        const card = cardRef.current
        const previousActive = document.activeElement
        const selectable = () => {
          if (!card) return []
          const nodes = card.querySelectorAll('button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')
          return Array.from(nodes).filter((node) => node === document.activeElement || node.offsetParent !== null)
        }
        const timer = window.setTimeout(() => {
          const preferred = card && card.querySelector('[data-modal-autofocus]')
          const first = selectable()[0]
          const target = preferred || first || card
          if (target && typeof target.focus === 'function') {
            try { target.focus() } catch { /* 忽略失焦失败 */ }
          }
        }, 0)
        const onKeyDown = (event) => {
          if (event.key === 'Escape') {
            event.preventDefault()
            event.stopPropagation()
            onCloseRef.current?.()
            return
          }
          if (event.key !== 'Tab') return
          const items = selectable()
          if (!items.length) {
            event.preventDefault()
            if (card && typeof card.focus === 'function') card.focus()
            return
          }
          const first = items[0]
          const last = items[items.length - 1]
          const active = document.activeElement
          if (event.shiftKey) {
            if (active === first || !card || !card.contains(active)) {
              event.preventDefault()
              last.focus()
            }
          } else if (active === last || !card || !card.contains(active)) {
            event.preventDefault()
            first.focus()
          }
        }
        document.addEventListener('keydown', onKeyDown, true)
        return () => {
          window.clearTimeout(timer)
          document.removeEventListener('keydown', onKeyDown, true)
          if (previousActive && typeof previousActive.focus === 'function') {
            try { previousActive.focus() } catch { /* 忽略 */ }
          }
        }
      }, [])

      return h('div', {
        role: 'presentation',
        style: S.modalOverlay,
        onMouseDown: (event) => {
          if (event.target === event.currentTarget) onCloseRef.current?.()
        },
      },
      h('div', {
        ref: cardRef,
        role: 'dialog',
        'aria-modal': 'true',
        'aria-labelledby': titleId,
        tabIndex: -1,
        style: S.modalCard,
      },
      h('div', { style: S.modalHead },
        h('h2', { id: titleId, style: S.modalTitle }, title),
        h(Btn, { variant: 'ghost', small: true, onClick: onClose, title: t('common.close') }, '✕')),
      h('div', { style: S.modalBody }, children),
      footer ? h('div', { style: S.modalFoot }, footer) : null))
    }

    /** 二次确认弹窗；run 由调用方负责错误提示，弹窗只负责忙碌态与关闭。 */
    function ConfirmDialog(props) {
      const { t, title, description, confirmLabel, danger, run, onClose } = props
      const [busy, setBusy] = React.useState(false)
      const mounted = React.useRef(true)
      React.useEffect(() => () => { mounted.current = false }, [])
      const confirm = async () => {
        if (busy) return
        setBusy(true)
        try {
          await run()
        } catch (error) {
          // 调用方已在 run 内部提示错误；这里只保证弹窗可关闭。
          void error
        } finally {
          if (mounted.current) setBusy(false)
          onClose()
        }
      }
      return h(Modal, {
        t,
        title,
        onClose: () => {
          if (!busy) onClose()
        },
        footer: h('div', { style: S.modalActions },
          h(Btn, { t, onClick: () => { if (!busy) onClose() }, disabled: busy, autofocus: true }, t('common.cancel')),
          h(Btn, {
            t,
            variant: danger ? 'dangerSolid' : 'primary',
            onClick: confirm,
            busy,
          }, busy ? t('common.saving') : (confirmLabel || t('common.confirm')))),
      },
      description ? h('p', { style: S.modalText }, description) : null)
    }

    /** 空态。 */
    function EmptyState(props) {
      const { title, description, action } = props
      return h('div', { style: S.empty },
        h('div', { style: S.emptyTitle }, title),
        description ? h('div', { style: S.emptyDesc }, description) : null,
        action ? h('div', { style: { marginTop: 14 } }, action) : null)
    }

    /** 连接测试结果面板。 */
    function TestResultPanel(props) {
      const { t, busy, result, error, onTrust, trusting } = props
      if (busy) {
        return h('div', { role: 'status', 'aria-busy': 'true', style: S.testBox }, t('common.testing'))
      }
      if (error) {
        return h('div', { style: S.testBox }, h(Banner, { t, tone: 'error' }, describeError(t, error)))
      }
      if (!result) return null
      const code = result.error && result.error.code
      const changed = code === 'host-key-changed' || result.hostKeyStatus === 'changed'
      const failed = result.ok === false || Boolean(result.error)
      const tone = changed ? 'error' : failed ? 'error' : 'success'
      const headline = changed
        ? t('test.changed')
        : failed
          ? t('test.failed')
          : result.hostKeyStatus === 'new'
            ? t('test.successNew')
            : t('test.successKnown')
      const rows = []
      if (result.elapsedMs !== undefined && result.elapsedMs !== null) {
        rows.push({ label: t('test.elapsed'), value: `${result.elapsedMs} ms` })
      }
      if (result.keyType) rows.push({ label: t('test.keyType'), value: String(result.keyType) })
      if (result.fingerprint) rows.push({ label: t('test.fingerprint'), value: String(result.fingerprint) })
      const previous = result.error && result.error.details && result.error.details.previousFingerprint
      if (previous) rows.push({ label: t('test.previousFingerprint'), value: String(previous) })
      if (result.banner) rows.push({ label: t('test.banner'), value: String(result.banner).slice(0, 240) })
      if (failed && !changed) rows.push({ label: '', value: describeError(t, result.error), wide: true })
      const trustFingerprint = result.fingerprint || (result.error && result.error.details && result.error.details.fingerprint)
      return h('div', { style: S.testBox },
        h(Banner, { t, tone }, headline),
        rows.length
          ? h('div', { style: S.detailList }, rows.map((row, index) => h('div', { key: `${row.label}-${index}`, style: S.detailRow },
            row.label ? h('span', { style: S.detailLabel }, row.label) : null,
            h('span', { style: row.wide ? S.detailValueWide : S.detailValue }, row.value))))
          : null,
        changed && onTrust
          ? h('div', { style: { display: 'flex', justifyContent: 'flex-start' } },
            h(Btn, {
              t,
              variant: 'primary',
              small: true,
              disabled: trusting,
              onClick: () => onTrust(trustFingerprint),
            }, trusting ? t('test.trusting') : t('test.trust')))
          : null)
    }

    // ------------------------------------------------------------ 主机页

    /** 凭据状态 chips（只展示布尔，不展示任何明文）。 */
    function credentialChips(t, host) {
      const fields = (host && host.secret && host.secret.fields) || {}
      const chips = []
      if (host.auth === 'password') {
        chips.push({ id: 'password', tone: fields.password ? 'success' : 'muted', label: fields.password ? t('hosts.passwordSet') : t('hosts.passwordUnset') })
      }
      if (host.auth === 'key') {
        chips.push({ id: 'privateKey', tone: fields.privateKey ? 'success' : 'muted', label: fields.privateKey ? t('hosts.keySet') : t('hosts.keyUnset') })
        chips.push({ id: 'passphrase', tone: fields.passphrase ? 'success' : 'muted', label: fields.passphrase ? t('hosts.passphraseSet') : t('hosts.passphraseUnset') })
      }
      if (host.sudo || fields.sudoPassword) {
        chips.push({ id: 'sudoPassword', tone: fields.sudoPassword ? 'success' : 'muted', label: fields.sudoPassword ? t('hosts.sudoPasswordSet') : t('hosts.sudoPasswordUnset') })
      }
      return chips
    }

    /** 按 tag 分组；无 tag 归"未分组"。使用 Host 给的 groups 顺序与成员关系。 */
    function buildHostGroups(state) {
      const hosts = Array.isArray(state.hosts) ? state.hosts : []
      const byId = new Map(hosts.map((host) => [host.id, host]))
      const covered = new Set()
      const groups = []
      const sourceGroups = Array.isArray(state.groups) ? state.groups : []
      for (const group of sourceGroups) {
        const list = Array.isArray(group.hostIds)
          ? group.hostIds.map((id) => byId.get(id)).filter(Boolean)
          : []
        if (!list.length) continue
        for (const host of list) covered.add(host.id)
        groups.push({ tag: group.tag, hosts: list })
      }
      const rest = hosts.filter((host) => !covered.has(host.id))
      if (rest.length) groups.push({ tag: '', hosts: rest })
      return groups
    }

    /** 单台主机行（含测试结果面板）。 */
    function HostRow(props) {
      const { t, host, test, onTest, onEdit, onDelete, onTrust } = props
      const knownHost = props.knownHost
      const credentials = credentialChips(t, host)
      const busy = Boolean(test && test.busy)
      const showTest = test && (test.busy || test.result || test.error)
      return h('div', { style: S.listRow },
        h('div', { style: S.rowMain },
          h('div', { style: S.rowTitleLine },
            h('span', { style: S.rowTitle, title: host.name }, host.name),
            h(Chip, { tone: 'neutral' }, host.auth === 'key' ? t('hosts.authKey') : t('hosts.authPassword')),
            host.sudo ? h(Chip, { tone: 'brand' }, t('hosts.sudo')) : null),
          h('div', { style: S.rowSub }, hostAddress(host)),
          host.note ? h('div', { style: { fontSize: 11, lineHeight: '17px', color: C.labelTertiary, wordBreak: 'break-word' } }, host.note) : null,
          h('div', { style: S.chipRow },
            (Array.isArray(host.tags) ? host.tags : []).map((tag) => h(Chip, { key: `tag-${tag}`, tone: 'brand' }, tag)),
            credentials.map((chip) => h(Chip, { key: chip.id, tone: chip.tone }, chip.label)),
            knownHost ? h(Chip, { tone: 'neutral', mono: true, title: knownHost.fingerprint }, knownHost.keyType || t('common.unknown')) : null)),
        h('div', { style: S.rowActions },
          h(Btn, { t, small: true, busy, onClick: () => onTest(host) }, busy ? t('hosts.testing') : t('hosts.test')),
          h(Btn, { t, small: true, onClick: () => onEdit(host) }, t('common.edit')),
          h(Btn, { t, variant: 'danger', small: true, onClick: () => onDelete(host) }, t('common.delete'))),
        showTest
          ? h('div', { style: { flexBasis: '100%', minWidth: 0, marginTop: 8 } },
            h(TestResultPanel, {
              t,
              busy: test.busy,
              result: test.result,
              error: test.error,
              onTrust: test.result && (test.result.hostKeyStatus === 'changed' || (test.result.error && test.result.error.code === 'host-key-changed'))
                ? (fingerprint) => onTrust(host, fingerprint)
                : null,
              trusting: Boolean(test.trusting),
            }))
          : null)
    }

    /** 主机页。 */
    function HostsTab(props) {
      const { t, state, tests, onAdd, onEdit, onDelete, onTest, onTrust } = props
      const groups = React.useMemo(() => buildHostGroups(state), [state])
      const knownByAddress = React.useMemo(() => {
        const map = new Map()
        for (const entry of Array.isArray(state.knownHosts) ? state.knownHosts : []) {
          map.set(`${String(entry.host).toLowerCase()}:${entry.port}`, entry)
        }
        return map
      }, [state.knownHosts])
      const hosts = Array.isArray(state.hosts) ? state.hosts : []
      const settings = state.settings || {}
      const idleMinutes = settings.sessionIdleMinutes
      const approval = settings.approvalMode === 'always'
        ? t('approval.always')
        : settings.approvalMode === 'trusted'
          ? t('approval.trusted')
          : t('approval.dangerous')

      return h('div', { role: 'tabpanel', id: 'remote-bash-panel-hosts', 'aria-labelledby': 'remote-bash-tab-hosts', style: S.tabPanel },
        hosts.length === 0
          ? h(EmptyState, {
            title: t('hosts.emptyTitle'),
            description: t('hosts.emptyDesc'),
            action: h(Btn, { t, variant: 'primary', onClick: onAdd }, t('hosts.add')),
          })
          : groups.map((group) => h('div', { key: group.tag || '__untagged__', style: { display: 'flex', flexDirection: 'column', gap: 6, minWidth: 0 } },
            h('div', { style: S.groupHead },
              h('span', { style: S.groupTitle }, group.tag ? `@${group.tag}` : t('hosts.groupUntagged')),
              h('span', { style: S.groupCount }, String(group.hosts.length))),
            h('div', { style: S.list }, group.hosts.map((host, index) => h('div', {
              key: host.id,
              style: index === 0 ? undefined : S.listRowDivided,
            }, h(HostRow, {
              t,
              host,
              test: tests[host.id],
              knownHost: knownByAddress.get(`${String(host.host).toLowerCase()}:${host.port}`),
              onTest,
              onEdit,
              onDelete,
              onTrust,
            })))))),
        h('div', { style: S.metaBox },
          h('div', { style: S.metaRow },
            h('span', null, `${t('meta.approval')}: ${approval}`),
            h('span', { 'aria-hidden': 'true' }, '·'),
            h('span', null, `${t('meta.timeout')}: ${settings.defaultTimeoutSec ?? '—'}s`),
            h('span', { 'aria-hidden': 'true' }, '·'),
            h('span', null, `${t('meta.parallel')}: ${settings.maxParallelHosts ?? '—'}`),
            h('span', { 'aria-hidden': 'true' }, '·'),
            h('span', null, `${t('meta.idle')}: ${format(t('meta.minutes'), { minutes: idleMinutes ?? '—' })}`),
            h('span', { 'aria-hidden': 'true' }, '·'),
            h('span', null, `${t('meta.credentialsAvailable')}: ${state.credentialsAvailable ? '✓' : '✕'}`)),
          settings.dataDir
            ? h('div', { style: S.metaRow },
              h('span', null, `${t('meta.dataDir')}:`),
              h('span', { style: S.metaMono }, settings.dataDir))
            : null))
    }

    // ------------------------------------------------------------ 已知主机页

    function KnownHostsTab(props) {
      const { t, state, onForget } = props
      const entries = Array.isArray(state.knownHosts) ? state.knownHosts : []
      const panelProps = { role: 'tabpanel', id: 'remote-bash-panel-knownHosts', 'aria-labelledby': 'remote-bash-tab-knownHosts', style: S.tabPanel }
      if (!entries.length) {
        return h('div', panelProps,
          h(EmptyState, { title: t('knownHosts.emptyTitle'), description: t('knownHosts.emptyDesc') }))
      }
      const rows = entries.map((entry, index) => h('div', {
        key: `${entry.host}:${entry.port}`,
        style: mergeStyles(S.listRow, index === 0 ? undefined : S.listRowDivided),
      },
      h('div', { style: S.rowMain },
        h('div', { style: S.rowTitleLine },
          h('span', { style: S.rowSub }, `${entry.host}:${entry.port}`),
          h(Chip, { tone: 'neutral', mono: true }, entry.keyType || t('common.unknown'))),
        h('div', { style: { fontSize: 11, lineHeight: '18px', color: C.labelPrimary, fontFamily: MONO, wordBreak: 'break-all' } }, entry.fingerprint),
        h('div', { style: S.hintLine },
          `${t('knownHosts.firstSeen')}: ${timeText(entry.firstSeenAt, t)} · ${t('knownHosts.lastSeen')}: ${timeText(entry.lastSeenAt, t)}`)),
      h('div', { style: S.rowActions },
        h(Btn, { t, variant: 'danger', small: true, onClick: () => onForget(entry) }, t('knownHosts.forget')))))
      return h('div', panelProps, h('div', { style: S.list }, rows))
    }

    // ------------------------------------------------------------ 会话页

    function SessionsTab(props) {
      const { t, state, onCloseSession, onCloseAll } = props
      const sessions = Array.isArray(state.sessions) ? state.sessions : []
      const idleMinutes = (state.settings && state.settings.sessionIdleMinutes) ?? '—'
      const panelProps = { role: 'tabpanel', id: 'remote-bash-panel-sessions', 'aria-labelledby': 'remote-bash-tab-sessions', style: S.tabPanel }
      const headerRow = h('div', { style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' } },
        h('div', { style: S.hintLine }, format(t('sessions.idleHint'), { minutes: idleMinutes })),
        h(Btn, { t, small: true, variant: 'danger', disabled: sessions.length === 0, onClick: onCloseAll }, t('sessions.closeAll')))
      if (!sessions.length) {
        return h('div', panelProps,
          headerRow,
          h(EmptyState, { title: t('sessions.emptyTitle'), description: t('sessions.emptyDesc') }))
      }
      const rows = sessions.map((session, index) => h('div', {
        key: session.key,
        style: mergeStyles(S.listRow, index === 0 ? undefined : S.listRowDivided),
      },
      h('div', { style: S.sessionMain },
        h('div', { style: S.sessionTitleLine },
          h('span', { style: S.sessionTitle, title: session.label }, session.label || t('common.unknown')),
          session.hostName ? h(Chip, { tone: 'neutral' }, session.hostName) : null,
          h(Chip, { tone: 'muted' }, t('sessions.agent')),
          h('span', { style: S.monoTruncate, title: session.agentId || '' }, session.agentId || t('sessions.unknownAgent'))),
        h('div', { style: S.hintLine },
          `${t('sessions.created')}: ${timeText(session.createdAt, t)} · ${t('sessions.lastUsed')}: ${timeText(session.lastUsedAt, t)}`)),
      h('div', { style: S.rowActions },
        h(Btn, { t, small: true, onClick: () => onCloseSession(session) }, t('sessions.close')))))
      return h('div', panelProps, headerRow, h('div', { style: S.list }, rows))
    }

    // ------------------------------------------------------------ 主机表单（弹窗）

    /** 一个密码类字段：只显示"已设置"布尔，留空不修改，可清除/撤销。 */
    function SecretInput(props) {
      const { t, label, hint, id, value, placeholder, placeholderConfigured, configured, cleared, multiline, rows, disabled, onChange, onClear, onUndo } = props
      return h(Field, {
        label,
        hint,
        htmlFor: id,
      },
      h('div', { style: S.labelRow, 'aria-live': 'polite' },
        configured && !cleared ? h(Chip, { tone: 'success' }, t('form.secretConfigured')) : null,
        cleared ? h(Chip, { tone: 'warn' }, t('form.clearPending')) : null,
        (configured && !cleared && !disabled)
          ? h('button', { type: 'button', style: S.linkBtn, onClick: onClear }, t('common.clear'))
          : null,
        cleared && !disabled
          ? h('button', { type: 'button', style: S.linkBtn, onClick: onUndo }, t('common.undo'))
          : null),
      multiline
        ? h(TextArea, {
          id,
          value,
          disabled,
          rows: rows ?? 4,
          mono: true,
          placeholder: configured && !cleared ? placeholderConfigured : placeholder,
          onChange,
        })
        : h(TextInput, {
          id,
          value,
          disabled,
          type: 'password',
          autoComplete: 'new-password',
          placeholder: configured && !cleared ? placeholderConfigured : placeholder,
          onChange,
        }))
    }

    function HostFormModal(props) {
      const {
        t, host, state, credentialsAvailable,
        onClose, onSave, onTest, onApprove,
      } = props
      const ids = React.useId()
      const isEdit = Boolean(host && host.id)
      const existingFields = (host && host.secret && host.secret.fields) || {}

      const [name, setName] = React.useState(host ? host.name : '')
      const [address, setAddress] = React.useState(host ? host.host : '')
      const [port, setPort] = React.useState(String(host ? host.port : 22))
      const [username, setUsername] = React.useState(host ? host.username : '')
      const [auth, setAuth] = React.useState(host && host.auth === 'key' ? 'key' : 'password')
      const [keyPath, setKeyPath] = React.useState(host ? host.keyPath || '' : '')
      const [tags, setTags] = React.useState(host && Array.isArray(host.tags) ? host.tags.join(', ') : '')
      const [note, setNote] = React.useState(host ? host.note || '' : '')
      const [sudo, setSudo] = React.useState(Boolean(host && host.sudo))

      const [password, setPassword] = React.useState('')
      const [privateKey, setPrivateKey] = React.useState('')
      const [passphrase, setPassphrase] = React.useState('')
      const [sudoPassword, setSudoPassword] = React.useState('')
      const [cleared, setCleared] = React.useState({})
      const [formError, setFormError] = React.useState(null)
      const [busy, setBusy] = React.useState(false)
      const [testBusy, setTestBusy] = React.useState(false)
      const [testResult, setTestResult] = React.useState(null)
      const [testError, setTestError] = React.useState(null)
      const [trusting, setTrusting] = React.useState(false)
      const mounted = React.useRef(true)
      React.useEffect(() => () => { mounted.current = false }, [])

      const secretFields = SECRET_FIELDS
      const configured = {}
      for (const field of secretFields) configured[field] = Boolean(existingFields[field])

      const values = { password, privateKey, passphrase, sudoPassword }
      const setters = {
        password: setPassword,
        privateKey: setPrivateKey,
        passphrase: setPassphrase,
        sudoPassword: setSudoPassword,
      }

      const clearField = (field) => {
        setCleared((prev) => ({ ...prev, [field]: true }))
        setters[field]('')
      }
      const undoClear = (field) => {
        setCleared((prev) => {
          const next = { ...prev }
          delete next[field]
          return next
        })
      }
      /** 输入新值即撤销该字段的"待清除"状态。 */
      const changeSecret = (field) => (nextValue) => {
        setters[field](nextValue)
        if (nextValue) {
          setCleared((prev) => {
            if (!prev[field]) return prev
            const next = { ...prev }
            delete next[field]
            return next
          })
        }
      }

      /** 表单校验；返回字段标签数组，空数组表示通过。 */
      const validate = () => {
        const missing = []
        if (!name.trim()) missing.push(t('form.name'))
        if (!address.trim()) missing.push(t('form.host'))
        if (!username.trim()) missing.push(t('form.username'))
        const numericPort = Number(port)
        if (!Number.isInteger(numericPort) || numericPort < 1 || numericPort > 65535) {
          missing.push(t('form.port'))
        }
        return missing
      }

      const baseInput = () => {
        const input = {
          name: name.trim(),
          host: address.trim(),
          port: Number(port),
          username: username.trim(),
          auth,
          keyPath: auth === 'key' ? keyPath.trim() : '',
          tags: parseTags(tags),
          note: note.trim(),
          sudo: Boolean(sudo),
        }
        if (isEdit) input.id = host.id
        return input
      }

      const secretPayload = () => {
        const payload = {}
        for (const field of secretFields) {
          if (cleared[field]) continue
          const value = values[field]
          if (typeof value === 'string' && value.length > 0) payload[field] = value
        }
        return payload
      }

      const clearList = () => secretFields.filter((field) => cleared[field])

      const reportInvalid = () => {
        const missing = validate()
        if (!missing.length) return true
        setFormError(format(t('error.requiredFields'), { fields: missing.join(', ') }))
        return false
      }

      const submit = async () => {
        if (busy) return
        if (!reportInvalid()) return
        setFormError(null)
        setBusy(true)
        try {
          const payload = baseInput()
          const secrets = credentialsAvailable ? secretPayload() : {}
          if (Object.keys(secrets).length) payload.secret = secrets
          const clear = credentialsAvailable ? clearList() : []
          if (clear.length) payload.clear = clear
          await onSave(payload)
        } catch (error) {
          if (mounted.current) setFormError(describeError(t, error))
        } finally {
          if (mounted.current) setBusy(false)
        }
      }

      const runTest = async () => {
        if (testBusy) return
        if (!reportInvalid()) return
        setFormError(null)
        setTestError(null)
        setTestResult(null)
        setTestBusy(true)
        try {
          const payload = isEdit
            ? { id: host.id }
            : { draft: baseInput(), secret: credentialsAvailable ? secretPayload() : {} }
          const result = await onTest(payload)
          if (mounted.current) setTestResult(result)
        } catch (error) {
          if (mounted.current) setTestError(error)
        } finally {
          if (mounted.current) setTestBusy(false)
        }
      }

      const trust = async (fingerprint) => {
        if (trusting) return
        setTrusting(true)
        try {
          await onApprove({
            host: isEdit ? host.host : address.trim(),
            port: isEdit ? host.port : Number(port),
            fingerprint,
          })
          if (mounted.current) {
            setTestError(null)
            setTestResult(null)
          }
        } catch (error) {
          if (mounted.current) setTestError(error)
        } finally {
          if (mounted.current) setTrusting(false)
        }
      }

      const secretEditable = Boolean(credentialsAvailable)
      const testChanged = testResult && (testResult.hostKeyStatus === 'changed' || (testResult.error && testResult.error.code === 'host-key-changed'))

      return h(Modal, {
        t,
        title: isEdit ? t('form.editTitle') : t('form.addTitle'),
        onClose: () => {
          if (!busy) onClose()
        },
        footer: h(React.Fragment, null,
          h(TestResultPanel, {
            t,
            busy: testBusy,
            result: testResult,
            error: testError,
            onTrust: testChanged ? trust : null,
            trusting,
          }),
          h('div', { style: S.hintLine }, t('form.testHint')),
          h('div', { style: S.modalActions },
            h(Btn, { t, small: true, onClick: runTest, disabled: busy || testBusy }, testBusy ? t('common.testing') : t('common.test')),
            h('span', { style: { flex: '1 1 auto' } }),
            h(Btn, { t, onClick: () => { if (!busy) onClose() }, disabled: busy }, t('common.cancel')),
            h(Btn, { t, variant: 'primary', onClick: submit, busy: busy || testBusy }, busy ? t('common.saving') : t('common.save')))),
      },
      h('div', { style: S.formBody },
        formError ? h(Banner, { t, tone: 'error' }, formError) : null,
        !credentialsAvailable ? h(Banner, { t, tone: 'warn' }, t('form.secretUnavailable')) : null,
        h('div', { style: { display: 'flex', flexDirection: 'column', gap: 12 } },
          h('div', { style: S.formSectionTitle }, t('form.sectionBasics')),
          h('div', { style: S.formGrid },
            h(Field, { label: t('form.name'), required: true, htmlFor: `${ids}-name` },
              h(TextInput, { id: `${ids}-name`, value: name, placeholder: t('form.namePlaceholder'), onChange: setName, autoFocus: true })),
            h(Field, { label: t('form.port'), required: true, htmlFor: `${ids}-port`, hint: t('error.invalidPort') },
              h(TextInput, { id: `${ids}-port`, type: 'number', value: port, placeholder: '22', onChange: setPort }))),
          h('div', { style: S.formGrid },
            h(Field, { label: t('form.host'), required: true, htmlFor: `${ids}-host` },
              h(TextInput, { id: `${ids}-host`, value: address, placeholder: t('form.hostPlaceholder'), onChange: setAddress })),
            h(Field, { label: t('form.username'), required: true, htmlFor: `${ids}-username` },
              h(TextInput, { id: `${ids}-username`, value: username, placeholder: t('form.usernamePlaceholder'), onChange: setUsername, autoComplete: 'username' })))),
        h('div', { style: S.formSection },
          h('div', { style: S.formSectionTitle }, t('form.sectionAuth')),
          h(Field, { label: t('form.auth') },
            h(RadioGroup, {
              name: `${ids}-auth`,
              label: t('form.auth'),
              value: auth,
              options: [
                { value: 'password', label: t('form.authPassword') },
                { value: 'key', label: t('form.authKey') },
              ],
              onChange: setAuth,
            })),
          auth === 'key'
            ? h(Field, { label: t('form.keyPath'), htmlFor: `${ids}-keypath`, hint: t('form.keyPathHint') },
              h(TextInput, { id: `${ids}-keypath`, value: keyPath, placeholder: t('form.keyPathPlaceholder'), onChange: setKeyPath }))
            : null,
          auth === 'key'
            ? h(Field, { label: t('form.privateKey'), htmlFor: `${ids}-privatekey`, hint: t('form.privateKeyHint') },
              h('div', { style: S.labelRow },
                configured.privateKey && !cleared.privateKey ? h(Chip, { tone: 'success' }, t('form.secretConfigured')) : null,
                cleared.privateKey ? h(Chip, { tone: 'warn' }, t('form.clearPending')) : null,
                configured.privateKey && !cleared.privateKey && secretEditable
                  ? h('button', { type: 'button', style: S.linkBtn, onClick: () => clearField('privateKey') }, t('common.clear'))
                  : null,
                cleared.privateKey && secretEditable
                  ? h('button', { type: 'button', style: S.linkBtn, onClick: () => undoClear('privateKey') }, t('common.undo'))
                  : null),
              h(TextArea, {
                id: `${ids}-privatekey`,
                value: privateKey,
                rows: 4,
                mono: true,
                disabled: !secretEditable,
                placeholder: configured.privateKey && !cleared.privateKey ? t('form.privateKeyConfigured') : t('form.privateKeyPlaceholder'),
                onChange: changeSecret('privateKey'),
              }))
            : null,
          auth === 'key'
            ? h(SecretInput, {
              t,
              id: `${ids}-passphrase`,
              label: t('form.passphrase'),
              value: passphrase,
              configured: configured.passphrase,
              cleared: Boolean(cleared.passphrase),
              disabled: !secretEditable,
              placeholder: t('form.passphrasePlaceholder'),
              placeholderConfigured: t('form.passphraseConfigured'),
              onChange: changeSecret('passphrase'),
              onClear: () => clearField('passphrase'),
              onUndo: () => undoClear('passphrase'),
            })
            : h(SecretInput, {
              t,
              id: `${ids}-password`,
              label: t('form.password'),
              value: password,
              configured: configured.password,
              cleared: Boolean(cleared.password),
              disabled: !secretEditable,
              placeholder: t('form.passwordPlaceholder'),
              placeholderConfigured: t('form.passwordConfigured'),
              onChange: changeSecret('password'),
              onClear: () => clearField('password'),
              onUndo: () => undoClear('password'),
            }),
          h(SecretInput, {
            t,
            id: `${ids}-sudopassword`,
            label: t('form.sudoPassword'),
            hint: t('form.sudoPasswordHint'),
            value: sudoPassword,
            configured: configured.sudoPassword,
            cleared: Boolean(cleared.sudoPassword),
            disabled: !secretEditable,
            placeholder: t('form.sudoPasswordPlaceholder'),
            placeholderConfigured: t('form.sudoPasswordConfigured'),
            onChange: changeSecret('sudoPassword'),
            onClear: () => clearField('sudoPassword'),
            onUndo: () => undoClear('sudoPassword'),
          })),
        h('div', { style: S.formSection },
          h('div', { style: S.formSectionTitle }, t('form.sectionAdvanced')),
          h(Field, { label: t('form.tags'), htmlFor: `${ids}-tags`, hint: t('form.tagsHint') },
            h(TextInput, { id: `${ids}-tags`, value: tags, placeholder: t('form.tagsPlaceholder'), onChange: setTags })),
          h(Field, { label: t('form.note'), htmlFor: `${ids}-note` },
            h(TextInput, { id: `${ids}-note`, value: note, placeholder: t('form.notePlaceholder'), onChange: setNote })),
          h('div', { style: { display: 'flex', flexDirection: 'column', gap: 4 } },
            h(Switch, { label: t('form.sudoDefault'), checked: sudo, onChange: setSudo }),
            h('div', { style: S.fieldHint }, t('form.sudoDefaultHint'))))))
    }

    // ------------------------------------------------------------ 页面主体

    function RemoteBashSection(props) {
      const t = useT(props && props.t)
      const [data, setData] = React.useState(null)
      const [loadError, setLoadError] = React.useState(null)
      const [loading, setLoading] = React.useState(true)
      const [refreshing, setRefreshing] = React.useState(false)
      const [tab, setTab] = React.useState('hosts')
      const [notice, setNotice] = React.useState(null)
      const [modal, setModal] = React.useState(null)
      const [tests, setTests] = React.useState({})
      const [credentialsDismissed, setCredentialsDismissed] = React.useState(false)
      const mounted = React.useRef(true)
      React.useEffect(() => () => { mounted.current = false }, [])

      // 成功提示自动消失；错误/警告保留到下一次操作或手动关闭。
      React.useEffect(() => {
        if (!notice || notice.tone === 'error' || notice.tone === 'warn') return undefined
        const timer = window.setTimeout(() => {
          if (mounted.current) setNotice(null)
        }, 5000)
        return () => window.clearTimeout(timer)
      }, [notice])

      const showNotice = React.useCallback((next) => {
        if (mounted.current) setNotice(next)
      }, [])

      const applyState = React.useCallback((value) => {
        if (value && Array.isArray(value.hosts)) {
          if (mounted.current) setData(value)
          return true
        }
        return false
      }, [])

      const load = React.useCallback(async (quiet) => {
        if (quiet) {
          if (mounted.current) setRefreshing(true)
        } else if (mounted.current) {
          setLoading(true)
          setLoadError(null)
        }
        try {
          const value = await call('state')
          if (!mounted.current) return
          setData(value)
          setLoadError(null)
        } catch (error) {
          if (!mounted.current) return
          if (quiet) showNotice({ tone: 'error', text: describeError(t, error) })
          else setLoadError(error)
        } finally {
          if (mounted.current) {
            setLoading(false)
            setRefreshing(false)
          }
        }
      }, [t, showNotice])

      React.useEffect(() => {
        load(false)
        // 只在挂载时加载一次；刷新走按钮/操作返回值。
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, [])

      /** 执行一个变更操作，统一提示成功/失败；返回是否成功。 */
      const perform = React.useCallback(async (work, successText) => {
        try {
          const value = await work()
          const next = value && value.state
          if (!applyState(next)) {
            // 某些方法（例如关闭全部会话）返回 { closed, state }；state 缺失时兜底重读。
            await load(true)
          }
          if (successText) showNotice({ tone: 'success', text: successText })
          return true
        } catch (error) {
          showNotice({ tone: 'error', text: describeError(t, error) })
          return false
        }
      }, [t, applyState, load, showNotice])

      const setHostTest = React.useCallback((hostId, patch) => {
        setTests((prev) => ({ ...prev, [hostId]: { ...(prev[hostId] || {}), ...patch } }))
      }, [])

      const runHostTest = React.useCallback(async (payload) => {
        const result = await call('host.test', payload)
        if (result && result.hostKeyStatus === 'new') load(true)
        return result
      }, [load])

      const testHost = React.useCallback(async (host) => {
        setHostTest(host.id, { busy: true, result: null, error: null })
        try {
          const result = await runHostTest({ id: host.id })
          if (mounted.current) setHostTest(host.id, { busy: false, result })
        } catch (error) {
          if (mounted.current) setHostTest(host.id, { busy: false, error })
        }
      }, [runHostTest, setHostTest])

      const approveFingerprint = React.useCallback(async (target) => {
        const value = await call('knownHost.approve', {
          host: target.host,
          port: Number(target.port),
          fingerprint: target.fingerprint,
        })
        if (value && value.state) applyState(value.state)
        else load(true)
        showNotice({ tone: 'success', text: t('test.trusted') })
        return value
      }, [applyState, load, showNotice, t])

      const trustHost = React.useCallback(async (host, fingerprint) => {
        setHostTest(host.id, { trusting: true })
        try {
          await approveFingerprint({ host: host.host, port: host.port, fingerprint })
          setHostTest(host.id, { trusting: false, result: null, error: null })
        } catch (error) {
          setHostTest(host.id, { trusting: false })
          showNotice({ tone: 'error', text: describeError(t, error) })
        }
      }, [approveFingerprint, setHostTest, showNotice, t])

      const closeModal = React.useCallback(() => {
        if (mounted.current) setModal(null)
      }, [])

      // ---- 弹窗动作

      const openAddHost = React.useCallback(() => {
        setModal({ kind: 'host-form', host: null })
      }, [])

      const openEditHost = React.useCallback((host) => {
        setModal({ kind: 'host-form', host })
      }, [])

      const openDeleteHost = React.useCallback((host) => {
        setModal({
          kind: 'confirm',
          title: t('hosts.deleteConfirm'),
          description: format(t('hosts.deleteConfirmDesc'), { name: host.name }),
          confirmLabel: t('common.delete'),
          danger: true,
          run: async () => {
            await perform(() => call('host.delete', { id: host.id }), t('hosts.deleted'))
          },
        })
      }, [perform, t])

      const openForgetKnownHost = React.useCallback((entry) => {
        setModal({
          kind: 'confirm',
          title: t('knownHosts.forgetTitle'),
          description: format(t('knownHosts.forgetDesc'), { host: `${entry.host}:${entry.port}` }),
          confirmLabel: t('knownHosts.forget'),
          danger: true,
          run: async () => {
            try {
              const value = await call('knownHost.forget', { host: entry.host, port: entry.port })
              if (!applyState(value && value.state)) await load(true)
              if (value && value.removed === false) showNotice({ tone: 'warn', text: t('error.notFound') })
              else showNotice({ tone: 'success', text: t('knownHosts.forgotten') })
            } catch (error) {
              showNotice({ tone: 'error', text: describeError(t, error) })
            }
          },
        })
      }, [applyState, load, showNotice, t])

      const openCloseSession = React.useCallback((session) => {
        setModal({
          kind: 'confirm',
          title: t('sessions.closeTitle'),
          description: format(t('sessions.closeDesc'), { label: session.label || session.key }),
          confirmLabel: t('sessions.close'),
          danger: false,
          run: async () => {
            try {
              const value = await call('session.close', { key: session.key })
              // Host 当前返回 boolean；INTERFACE §3 约定 { state }。两种形态都兼容。
              if (!applyState(value && value.state)) await load(true)
              if (value === false) showNotice({ tone: 'warn', text: t('error.notFound') })
              else showNotice({ tone: 'success', text: t('sessions.closed') })
            } catch (error) {
              showNotice({ tone: 'error', text: describeError(t, error) })
            }
          },
        })
      }, [applyState, load, showNotice, t])

      const openCloseAllSessions = React.useCallback(() => {
        const count = data && Array.isArray(data.sessions) ? data.sessions.length : 0
        setModal({
          kind: 'confirm',
          title: t('sessions.closeAllTitle'),
          description: format(t('sessions.closeAllDesc'), { n: count }),
          confirmLabel: t('sessions.closeAll'),
          danger: true,
          run: async () => {
            try {
              const value = await call('session.closeAll')
              if (!applyState(value && value.state)) await load(true)
              const closed = value && typeof value.closed === 'number'
                ? value.closed
                : value && Array.isArray(value.closed)
                  ? value.closed.length
                  : count
              showNotice({ tone: 'success', text: format(t('sessions.closedAll'), { n: closed }) })
            } catch (error) {
              showNotice({ tone: 'error', text: describeError(t, error) })
            }
          },
        })
      }, [applyState, data, load, showNotice, t])

      const saveHost = React.useCallback(async (payload) => {
        const value = await call('host.save', payload)
        if (!applyState(value && value.state)) await load(true)
        showNotice({ tone: 'success', text: t('hosts.saved') })
        setTab('hosts')
        if (mounted.current) setModal(null)
        return value
      }, [applyState, load, showNotice, t])

      const saveHostForForm = React.useCallback(async (payload) => {
        // 表单内部会捕获异常并展示；这里只透传。
        return saveHost(payload)
      }, [saveHost])

      const formTest = React.useCallback(async (payload) => {
        return runHostTest(payload)
      }, [runHostTest])

      // ---- 渲染

      const tabs = [
        { id: 'hosts', label: t('tabs.hosts'), count: data && Array.isArray(data.hosts) ? data.hosts.length : 0 },
        { id: 'knownHosts', label: t('tabs.knownHosts'), count: data && Array.isArray(data.knownHosts) ? data.knownHosts.length : 0 },
        { id: 'sessions', label: t('tabs.sessions'), count: data && Array.isArray(data.sessions) ? data.sessions.length : 0 },
      ]

      const header = h('div', { style: S.header },
        h('div', { style: S.headerText },
          h('h1', { style: S.h1 }, t('page.title')),
          h('p', { style: S.desc }, t('page.description'))),
        h('div', { style: S.actions },
          h(Btn, { t, onClick: () => load(true), busy: loading || refreshing }, refreshing ? t('common.refreshing') : t('common.refresh')),
          h(Btn, { t, variant: 'primary', onClick: openAddHost }, t('hosts.add'))))

      if (loading && !data) {
        return h('div', { style: S.root },
          header,
          h('div', { role: 'status', 'aria-busy': 'true', style: S.centerState }, t('state.loading')))
      }

      if (!data && loadError) {
        return h('div', { style: S.root },
          header,
          h(Banner, { t, tone: 'error' }, `${t('state.loadFailed')} ${describeError(t, loadError)}`),
          h('div', null, h(Btn, { t, onClick: () => load(false) }, t('common.retry'))))
      }

      const safeData = data || { hosts: [], groups: [], knownHosts: [], sessions: [], settings: {}, credentialsAvailable: false }

      return h('div', { style: S.root },
        header,
        notice
          ? h(Banner, {
            t,
            tone: notice.tone || 'info',
            onDismiss: () => showNotice(null),
          }, notice.text)
          : null,
        safeData.credentialsAvailable === false && !credentialsDismissed
          ? h(Banner, { t, tone: 'warn', onDismiss: () => setCredentialsDismissed(true) }, t('credentials.unavailable'))
          : null,
        h(Tabs, { t, items: tabs, value: tab, onChange: setTab }),
        tab === 'hosts'
          ? h(HostsTab, {
            t,
            state: safeData,
            tests,
            onAdd: openAddHost,
            onEdit: openEditHost,
            onDelete: openDeleteHost,
            onTest: testHost,
            onTrust: trustHost,
          })
          : tab === 'knownHosts'
            ? h(KnownHostsTab, { t, state: safeData, onForget: openForgetKnownHost })
            : h(SessionsTab, { t, state: safeData, onCloseSession: openCloseSession, onCloseAll: openCloseAllSessions }),
        modal && modal.kind === 'host-form'
          ? h(HostFormModal, {
            key: modal.host ? `host-${modal.host.id}` : 'host-new',
            t,
            host: modal.host,
            credentialsAvailable: safeData.credentialsAvailable !== false,
            onClose: closeModal,
            onSave: saveHostForForm,
            onTest: formTest,
            onApprove: approveFingerprint,
          })
          : null,
        modal && modal.kind === 'confirm'
          ? h(ConfirmDialog, {
            t,
            title: modal.title,
            description: modal.description,
            confirmLabel: modal.confirmLabel,
            danger: modal.danger,
            run: modal.run,
            onClose: closeModal,
          })
          : null)
    }

    // ------------------------------------------------------------ 注册

    function apply(ctx) {
      // 文案：自建 zh/en 字典（键集一致）。
      ctx.effect(() => ctx.locale.register(NS, { zh, en }), 'remote-bash: dictionaries')
      translate = ctx.locale.bind(NS)
      subscribeLocale = (listener) => ctx.locale.subscribe(listener)

      // Browser -> Host RPC（复用 DSH connection.rpc.call 的信封）。
      rpcCall = (method, payload, signal) => ctx.connection.rpc.call(
        '/api',
        RPC_ENDPOINT,
        { method, payload: payload ?? {} },
        signal,
      )

      // settings.section：list 槽，注册后按 order 出现在设置面板左侧导航。
      ctx.slots.inject('settings.section', () => ctx.slots.register({
        name: 'settings.section',
        id: 'remote-bash',
        order: 30,
        label: () => translate('settings.title'),
        locale: NS,
      }, RemoteBashSection))
    }

    return { apply, inject: ['slots', 'locale', 'connection'] }
  },
})
