/**
 * Opt-in integration against real OpenSSH and sudo, provisioned exclusively by
 * openssh-ci.sh in the disposable CI container. No local provisioning occurs.
 * RUN_OPENSSH_TESTS=1 is fail-closed: missing configuration fails, never skips.
 */
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { buildCommand, createSshClient } from '../host/ssh.js'
import { openShell } from '../host/shell.js'

const enabled = process.env.RUN_OPENSSH_TESTS === '1'
const skip = enabled ? false : 'real OpenSSH/sudo integration requires the disposable CI fixture'

function required(name) {
  assert.ok(process.env[name], `enabled OpenSSH integration requires ${name}`)
  return process.env[name]
}

function successful(result) {
  assert.equal(result.timedOut, false, 'remote command must complete before its deadline')
  assert.equal(result.code, 0, 'remote command must exit successfully')
}

function noSecret(result, ...secrets) {
  // Do not include actual output/passwords in assertion diagnostics.
  for (const secret of secrets) assert.equal(result.output.includes(secret), false, 'output must not expose a credential')
}

test('real OpenSSH + sudo integration', { skip, timeout: 120000 }, async (t) => {
  assert.equal(process.platform, 'linux', 'the enabled fixture must run on Linux')
  const port = Number(required('RB_OPENSSH_PORT'))
  assert.ok(Number.isInteger(port) && port > 1024 && port <= 65535)
  const password = required('RB_OPENSSH_PASSWORD')
  const users = { password: required('RB_OPENSSH_AUTH_USER'), nopasswd: required('RB_OPENSSH_NOPASS_USER') }
  const privateKey = await readFile(required('RB_OPENSSH_KEY'), 'utf8')
  const expectedFingerprint = required('RB_OPENSSH_FINGERPRINT')
  // Pin the fixture's independently generated host key. Do not weaken verification.
  const ssh = createSshClient({
    knownHosts: {
      async verify({ fingerprint, keyType }) {
        assert.equal(fingerprint, expectedFingerprint, 'server must present the fixture host key')
        return { fingerprint, keyType, status: 'known' }
      },
    },
  })
  const clients = new Set()
  const shells = new Set()
  t.after(async () => {
    await Promise.allSettled([...shells].map((shell) => shell.close()))
    for (const client of clients) client.destroy()
  })

  async function connect(user = users.password) {
    const { client } = await ssh.connect({
      id: user, name: user, host: '127.0.0.1', port, username: user, auth: 'key',
    }, { privateKey }, { timeoutMs: 10000 })
    clients.add(client)
    return client
  }

  const client = await connect()
  const nopassClient = await connect(users.nopasswd)
  const exec = (target, command, extra = {}) => ssh.exec(target, { command, timeoutMs: 10000, maxOutputBytes: 1048576, ...extra })
  const sudo = async (target, command, secret = password) => {
    const built = buildCommand({ command, sudo: true, sudoPassword: secret })
    assert.equal(built.remoteCommand.includes(secret), false, 'SSH exec command must not contain the password')
    const result = await exec(target, built.remoteCommand, { sudoInput: built.sudoInput })
    noSecret(result, secret, password)
    return result
  }
  const freshAuth = async () => successful(await exec(client, 'sudo -K'))

  await t.test('persistent shell has no PTY, preserves state and isolates command stdin', async () => {
    const shell = await openShell(client, { timeoutMs: 10000 })
    shells.add(shell)
    const result = await shell.run('if test -t 0 || test -t 1 || test -t 2; then exit 91; fi; printf NO_PTY', { timeoutMs: 10000 })
    successful(result)
    assert.equal(result.output.trim(), 'NO_PTY')
    successful(await shell.run('export RB_INTEGRATION_STATE=retained; cd /tmp', { timeoutMs: 10000 }))
    const state = await shell.run('printf "%s:%s" "$RB_INTEGRATION_STATE" "$PWD"', { timeoutMs: 10000 })
    successful(state)
    assert.equal(state.output.trim(), 'retained:/tmp')
    const eof = await shell.run('if IFS= read -r value; then printf UNEXPECTED_INPUT; exit 92; fi; cat; printf STDIN_EOF', { timeoutMs: 10000 })
    successful(eof)
    assert.equal(eof.output.trim(), 'STDIN_EOF')
  })

  await t.test('fresh password authentication succeeds and sudo child gets EOF', async () => {
    await freshAuth()
    const needsPassword = await exec(client, 'sudo -n -- bash -c true')
    assert.notEqual(needsPassword.code, 0, 'fixture must require a password before authentication')
    const result = await sudo(client, 'test "$(id -u)" = 0 || exit 96; if IFS= read -r value; then exit 93; fi; cat; printf AUTHENTICATED_EOF')
    successful(result)
    assert.equal(result.output.trim(), 'AUTHENTICATED_EOF')
  })

  await t.test('wrong password cannot execute the command', async () => {
    await freshAuth()
    const wrong = `wrong-${crypto.randomBytes(20).toString('hex')}`
    let result
    try {
      result = await sudo(client, 'printf MUST_NOT_RUN', wrong)
    } catch (error) {
      assert.equal(error.code, 'sudo-auth-failed', 'only an explicit authentication rejection satisfies this test')
      return
    }
    assert.equal(result.timedOut, false, 'authentication rejection must not merely time out')
    assert.notEqual(result.code, 0)
    assert.equal(result.output.includes('MUST_NOT_RUN'), false)
  })

  await t.test('cached authentication does not send a supplied password to stdin', async () => {
    await freshAuth()
    successful(await sudo(client, 'printf CACHE_PRIMED'))
    successful(await exec(client, 'sudo -n -- bash -c true'))
    // The intentionally incorrect credential proves the no-prompt cache path.
    const unused = `cached-unused-${crypto.randomBytes(20).toString('hex')}`
    const result = await sudo(client, 'if IFS= read -r value; then exit 94; fi; cat; printf CACHED_EOF', unused)
    successful(result)
    assert.equal(result.output.trim(), 'CACHED_EOF')
  })

  await t.test('NOPASSWD with no timestamp keeps unused credentials out of stdin', async () => {
    successful(await exec(nopassClient, 'sudo -K'))
    successful(await exec(nopassClient, 'sudo -n -- bash -c true'))
    const unused = `nopass-unused-${crypto.randomBytes(20).toString('hex')}`
    const result = await sudo(nopassClient, 'if IFS= read -r value; then exit 95; fi; cat; printf NOPASSWD_EOF', unused)
    successful(result)
    assert.equal(result.output.trim(), 'NOPASSWD_EOF')
  })

  await t.test('persistent sudo authenticates, isolates stdin and keeps the shell usable', async () => {
    await freshAuth()
    const shell = await openShell(client, { timeoutMs: 10000 })
    shells.add(shell)
    const built = buildCommand({ command: 'test "$(id -u)" = 0 || exit 96; cat; printf PERSISTENT_EOF', sudo: true, sudoPassword: password })
    const result = await shell.run(built.remoteCommand, { sudoInput: built.sudoInput, timeoutMs: 10000 })
    successful(result)
    noSecret(result, password)
    assert.equal(result.output.trim(), 'PERSISTENT_EOF')
    successful(await exec(client, 'sudo -n -- bash -c true'))
    const unused = `persistent-cached-${crypto.randomBytes(20).toString('hex')}`
    const cached = buildCommand({ command: 'cat; printf PERSISTENT_CACHED_EOF', sudo: true, sudoPassword: unused })
    const cachedResult = await shell.run(cached.remoteCommand, { sudoInput: cached.sudoInput, timeoutMs: 10000 })
    successful(cachedResult)
    noSecret(cachedResult, unused, password)
    assert.equal(cachedResult.output.trim(), 'PERSISTENT_CACHED_EOF')
    const next = await shell.run('printf NEXT_COMMAND', { timeoutMs: 10000 })
    successful(next)
    assert.equal(next.output.trim(), 'NEXT_COMMAND')
  })

  await t.test('persistent NOPASSWD does not leave authentication bytes in the shell', async () => {
    const shell = await openShell(nopassClient, { timeoutMs: 10000 })
    shells.add(shell)
    const unused = `persistent-nopass-${crypto.randomBytes(20).toString('hex')}`
    const built = buildCommand({ command: 'cat; printf PERSISTENT_NOPASSWD_EOF', sudo: true, sudoPassword: unused })
    const result = await shell.run(built.remoteCommand, { sudoInput: built.sudoInput, timeoutMs: 10000 })
    successful(result)
    noSecret(result, unused, password)
    assert.equal(result.output.trim(), 'PERSISTENT_NOPASSWD_EOF')
    const next = await shell.run('printf STILL_SYNCHRONIZED', { timeoutMs: 10000 })
    successful(next)
    assert.equal(next.output.trim(), 'STILL_SYNCHRONIZED')
  })

  await t.test('live remote process argv never contains the synthetic sudo password', async () => {
    await freshAuth()
    const marker = `RB_ARGV_${crypto.randomBytes(12).toString('hex')}`
    const work = sudo(client, `printf '${marker}'; sleep 3; :`).then(
      (value) => ({ value }), (error) => ({ error }),
    )
    // Independent SSH channel observes the target while sudo/bash is alive.
    // Use ps from the NOPASSWD account, scoped to the exact test marker in memory.
    let observed = false
    const deadline = Date.now() + 2500
    while (Date.now() < deadline) {
      const snapshot = await sudo(nopassClient, 'ps -eo args= -ww')
      successful(snapshot)
      assert.equal(snapshot.truncated, false, 'argv snapshot must not omit processes through truncation')
      noSecret(snapshot, password)
      if (snapshot.output.includes(marker)) { observed = true; break }
      await new Promise((resolve) => setTimeout(resolve, 25))
    }
    const completed = await work
    if (completed.error) throw completed.error
    successful(completed.value)
    assert.equal(observed, true, 'must observe the live test process, not just an empty process snapshot')
    assert.equal(completed.value.output.trim(), marker)
  })
})
