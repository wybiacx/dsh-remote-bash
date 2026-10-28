/**
 * End-to-end tests for the model-facing tools (host/tools.js) against the mock
 * SSH server, including the danger-assessment -> DSH approval gate wiring in
 * the tool layer, sudo approval, tool-level sessions and transfers.
 */

import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { after, before, beforeEach, test } from 'node:test'

import { installTools } from '../host/tools.js'
import { createApprovalGate } from '../host/approval.js'
import {
  cleanupTempDirs,
  createFakeApproval,
  createRig,
  makeTempDir,
  MOCK_PASSWORD,
  MOCK_SUDO_PASSWORD,
  quietLogger,
  saveMockHost,
  startMockServer,
} from './helpers.mjs'

let mock
let rig
let harness

const AGENT = { id: 'agent-tools' }

function installHarness({ service, gate, config }) {
  const registered = new Map()
  const ctx = {
    tools: {
      register(tool) {
        registered.set(tool.name, tool)
        return () => registered.delete(tool.name)
      },
    },
    effect(factory) {
      return factory()
    },
  }
  const dispose = installTools(ctx, { service, gate, config })
  return {
    tools: registered,
    dispose() {
      try {
        dispose?.()
      } catch {
        /* ignore */
      }
    },
  }
}

function tool(name) {
  const found = harness.tools.get(name)
  assert.ok(found, `tool ${name} was not registered`)
  return found
}

function execContext(overrides = {}) {
  return { agent: AGENT, callId: 'call-1', signal: undefined, ...overrides }
}

function textOf(blocks) {
  assert.ok(Array.isArray(blocks), 'tool.output.render must return content blocks')
  return blocks.map((block) => block.text ?? '').join('\n')
}

before(async () => {
  mock = await startMockServer()
  rig = createRig()
  await saveMockHost(rig, mock, { name: 'web-1', tags: ['web'] })
  await saveMockHost(rig, mock, { name: 'db-1', tags: ['db'] })
  await saveMockHost(rig, mock, { name: 'sudo-default', tags: [], sudo: true })
  harness = installHarness({ service: rig.service, gate: rig.gate, config: rig.settings })
})

beforeEach(() => {
  rig.approval.calls.length = 0
  rig.approval.outcome = 'allowed-once'
})

after(async () => {
  harness?.dispose()
  await mock?.close()
  await rig?.dispose()
  cleanupTempDirs()
})

test('remote_hosts: lists hosts, groups, credential flags and renders text', async () => {
  const value = await tool('remote_hosts').execute()
  assert.equal(value.approvalMode, 'dangerous')
  assert.equal(value.credentialsAvailable, true)
  assert.equal(value.dataDir, rig.root)
  assert.equal(value.hosts.length, 3)
  const web = value.hosts.find((host) => host.name === 'web-1')
  assert.equal(web.secret.fields.password, true)
  assert.equal(web.secret.fields.sudoPassword, true)
  assert.deepEqual(web.tags, ['web'])
  assert.ok(value.groups.some((group) => group.tag === 'web' && group.hostIds.includes(web.id)))

  const text = textOf(tool('remote_hosts').output.render({}, value))
  assert.match(text, /已配置 3 台远程主机/)
  assert.match(text, /web-1/)
  assert.match(text, /密码/)
  assert.ok(!text.includes('⚠'), 'configured hosts render no warning')
})

test('remote_bash: runs safe commands without approval', async () => {
  const value = await tool('remote_bash').execute(
    { targets: 'web-1', command: 'echo tool-ok' },
    execContext(),
  )
  assert.equal(rig.approval.calls.length, 0)
  assert.equal(value.hosts[0].status, 'ok')
  assert.equal(value.hosts[0].output, 'tool-ok\n')
  const text = textOf(tool('remote_bash').output.render({ targets: 'web-1', command: 'echo tool-ok' }, value))
  assert.match(text, /tool-ok/, 'the output is rendered')
  assert.ok(!text.includes('远程命令'), 'no command echo')
  assert.ok(!text.includes('结果：'), 'no summary noise')
})

test('remote_bash: dangerous command asks the approval gate, allowed-once executes it', async () => {
  const command = 'dd if=/dev/zero of=/dev/null bs=1 count=1'
  const description = '写入测试数据（无副作用）'
  const bashTool = tool('remote_bash')
  const value = await bashTool.execute({ targets: 'web-1', command, description }, execContext())

  assert.equal(rig.approval.calls.length, 1)
  const request = rig.approval.calls[0]
  assert.equal(request.agent, AGENT)
  assert.equal(request.toolName, 'remote_bash')
  assert.equal(request.callId, 'call-1')
  assert.match(request.reason, /直接写块设备/)
  assert.match(request.reason, /web-1/)
  assert.match(request.reason, /写入测试数据（无副作用）/, 'the audit reason carries the description')
  assert.match(request.displayReason.en, /Run/)
  assert.match(request.displayReason.zh, /写入测试数据（无副作用）/)
  assert.ok(!request.displayReason.zh.includes('dd if=/dev/zero'), 'user-visible copy stays concise')

  assert.equal(value.description, description)
  assert.equal(value.hosts[0].status, 'ok', JSON.stringify(value.hosts[0]))
  assert.equal(value.hosts[0].exitCode, 0)

  const rendered = textOf(bashTool.output.render({ targets: 'web-1', command }, value))
  assert.match(rendered, /records/)
  const call = bashTool.presentCall({ targets: 'web-1', command, description })
  assert.equal(call.description, description)
})

test('remote_bash: rejected/cancelled approval blocks execution', async () => {
  for (const outcome of ['rejected', 'cancelled']) {
    rig.approval.calls.length = 0
    rig.approval.outcome = outcome
    await assert.rejects(
      tool('remote_bash').execute({ targets: 'web-1', command: 'rm -rf /' }, execContext()),
      (error) => {
        assert.equal(error.code, 'approval-denied')
        assert.ok(error.message.length > 0)
        return true
      },
    )
    assert.equal(rig.approval.calls.length, 1)
  }
})

test('remote_bash: approvalMode=always gates every command', async () => {
  const fakeApproval = createFakeApproval('rejected')
  const alwaysGate = createApprovalGate({ approval: fakeApproval, mode: 'always', logger: quietLogger })
  const alwaysHarness = installHarness({
    service: rig.service,
    gate: alwaysGate,
    config: { ...rig.settings, approvalMode: 'always' },
  })
  try {
    const bashTool = alwaysHarness.tools.get('remote_bash')
    await assert.rejects(
      bashTool.execute({ targets: 'web-1', command: 'echo harmless' }, execContext()),
      { code: 'approval-denied' },
    )
    assert.equal(fakeApproval.calls.length, 1)

    fakeApproval.outcome = 'allowed-once'
    const value = await bashTool.execute({ targets: 'web-1', command: 'echo harmless' }, execContext())
    assert.equal(value.hosts[0].status, 'ok')
    assert.equal(fakeApproval.calls.length, 2)
  } finally {
    alwaysHarness.dispose()
  }
})

test('remote_bash: sudo triggers approval and runs with the stored sudo password', async () => {
  const value = await tool('remote_bash').execute(
    { targets: 'web-1', command: 'echo sudo-tool', sudo: true },
    execContext(),
  )
  assert.equal(rig.approval.calls.length, 1)
  assert.match(rig.approval.calls[0].reason, /sudo 提权/)
  assert.equal(value.sudo, true)
  assert.equal(value.hosts[0].status, 'ok', JSON.stringify(value.hosts[0]))
  assert.equal(value.hosts[0].output, 'sudo-tool\n')
  assert.ok(MOCK_SUDO_PASSWORD.length > 0)
})

test('remote_bash: hosts with default sudo also require approval and elevate', async () => {
  const value = await tool('remote_bash').execute(
    { targets: 'sudo-default', command: 'echo default-sudo' },
    execContext(),
  )
  assert.equal(rig.approval.calls.length, 1)
  assert.match(rig.approval.calls[0].reason, /sudo/)
  assert.equal(value.sudo, true, 'top-level sudo reports effective elevation')
  assert.equal(value.hosts[0].status, 'ok', JSON.stringify(value.hosts[0]))
  assert.equal(value.hosts[0].output, 'default-sudo\n')
})

test('remote_bash: tool sessions persist cd/export and remote_sessions lists/closes them', async () => {
  const bashTool = tool('remote_bash')
  const sessionTool = tool('remote_sessions')

  const first = await bashTool.execute(
    {
      targets: 'web-1',
      command: 'mkdir -p "$HOME/tool-persist" && cd "$HOME/tool-persist" && export TOOL_SESSION_VALUE=9',
      session: 'tool-s',
    },
    execContext(),
  )
  assert.equal(first.hosts[0].status, 'ok', JSON.stringify(first.hosts[0]))

  const second = await bashTool.execute(
    { targets: 'web-1', command: 'pwd; echo "v=$TOOL_SESSION_VALUE"', session: 'tool-s' },
    execContext(),
  )
  assert.equal(second.hosts[0].status, 'ok')
  assert.equal(second.hosts[0].output, `${mock.homeDir}/tool-persist\nv=9\n`)

  const listed = await sessionTool.execute({ action: 'list' }, execContext())
  assert.equal(listed.action, 'list')
  assert.equal(listed.sessions.length, 1)
  assert.equal(listed.sessions[0].label, 'tool-s')
  assert.equal(listed.sessions[0].hostId, (await rig.service.resolveTargets('web-1'))[0].id)

  const closed = await sessionTool.execute({ action: 'close', session: 'tool-s' }, execContext())
  assert.equal(closed.action, 'close')
  assert.equal(closed.closed, 1)
  assert.equal(closed.sessions.length, 0)

  const listText = textOf(sessionTool.output.render({ action: 'list' }, { action: 'list', sessions: [] }))
  assert.equal(listText, '当前没有持久会话。')
})

test('remote_sessions: close without a session name closes this agent sessions only', async () => {
  const bashTool = tool('remote_bash')
  const sessionTool = tool('remote_sessions')
  await bashTool.execute({ targets: 'web-1', command: 'true', session: 'one' }, execContext())
  await bashTool.execute({ targets: 'web-1', command: 'true', session: 'two' }, execContext())
  await bashTool.execute(
    { targets: 'web-1', command: 'true', session: 'other-agent' },
    execContext({ agent: { id: 'agent-other' } }),
  )

  const closed = await sessionTool.execute({ action: 'close' }, execContext())
  assert.equal(closed.closed, 2)
  assert.equal(closed.sessions.length, 0)

  const other = await sessionTool.execute({ action: 'list' }, execContext({ agent: { id: 'agent-other' } }))
  assert.equal(other.sessions.length, 1)
  await rig.service.closeAllSessions()
})

test('remote_upload/remote_download: tools transfer files and report results', async () => {
  const localDir = makeTempDir('rb-tool-transfer-')
  const source = path.join(localDir, 'tool-source.txt')
  const payload = 'tool transfer payload'
  fs.writeFileSync(source, payload)

  const uploadValue = await tool('remote_upload').execute(
    { targets: 'web-1', localPath: source, remotePath: '~/tool-upload.txt' },
    execContext(),
  )
  assert.equal(uploadValue.action, 'upload')
  assert.equal(uploadValue.hosts[0].status, 'ok')
  assert.equal(uploadValue.hosts[0].bytes, Buffer.byteLength(payload))
  assert.equal(fs.readFileSync(path.join(mock.homeDir, 'tool-upload.txt'), 'utf8'), payload)

  const target = path.join(localDir, 'tool-downloaded.txt')
  const downloadValue = await tool('remote_download').execute(
    { targets: 'web-1', remotePath: '~/tool-upload.txt', localPath: target },
    execContext(),
  )
  assert.equal(downloadValue.action, 'download')
  assert.equal(downloadValue.hosts[0].status, 'ok')
  assert.equal(downloadValue.hosts[0].localPath, target)
  assert.equal(fs.readFileSync(target, 'utf8'), payload)

  // localPath as an existing directory: single host lands as <basename>,
  // multiple hosts as <name>-<basename>.
  const downloadDir = makeTempDir('rb-tool-dl-dir-')
  const singleDirValue = await tool('remote_download').execute(
    { targets: 'web-1', remotePath: '~/tool-upload.txt', localPath: downloadDir },
    execContext(),
  )
  assert.equal(singleDirValue.hosts[0].status, 'ok', JSON.stringify(singleDirValue.hosts[0]))
  assert.equal(singleDirValue.hosts[0].localPath, path.join(downloadDir, 'tool-upload.txt'))
  assert.equal(fs.readFileSync(path.join(downloadDir, 'tool-upload.txt'), 'utf8'), payload)

  const multiDirValue = await tool('remote_download').execute(
    { targets: 'web-1,db-1', remotePath: '~/tool-upload.txt', localPath: downloadDir },
    execContext(),
  )
  assert.ok(multiDirValue.hosts.every((entry) => entry.status === 'ok'))
  for (const name of ['web-1', 'db-1']) {
    const file = path.join(downloadDir, `${name}-tool-upload.txt`)
    assert.equal(fs.readFileSync(file, 'utf8'), payload)
  }

  const uploadText = textOf(tool('remote_upload').output.render({}, uploadValue))
  assert.match(uploadText, /上传/)
  assert.match(uploadText, /成功/)
})

test('remote_bash/remote_upload/remote_download: argument validation', async () => {
  const bashTool = tool('remote_bash')
  await assert.rejects(bashTool.execute({ targets: 'web-1', command: '' }, execContext()), {
    code: 'invalid-command',
  })
  await assert.rejects(bashTool.execute({ targets: '', command: 'echo hi' }, execContext()), {
    code: 'unknown-target',
  })
  await assert.rejects(
    bashTool.execute({ targets: 'web-1', command: 'echo hi', session: 'bad session!' }, execContext()),
    { code: 'invalid-session' },
  )
  await assert.rejects(
    tool('remote_upload').execute({ targets: 'web-1', localPath: '', remotePath: '~/x' }, execContext()),
    { code: 'invalid-path' },
  )
  await assert.rejects(
    tool('remote_download').execute({ targets: 'web-1', localPath: '/tmp/x', remotePath: '' }, execContext()),
    { code: 'invalid-path' },
  )
})
