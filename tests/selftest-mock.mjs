/**
 * Self-test for `tests/mock-ssh-server.mjs`, using a native ssh2 Client.
 *
 * This deliberately does NOT import host/**: it proves the fixture is a real
 * SSH server (auth / exec / shell / sftp / host keys) before the end-to-end
 * tests build on it.
 *
 * Run: node tests/selftest-mock.mjs
 */

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import ssh2 from 'ssh2'

import {
  createMockServer,
  fingerprintOf,
  MOCK_PASSWORD,
  MOCK_SUDO_PASSWORD,
  MOCK_USERNAME,
} from './mock-ssh-server.mjs'

const { Client } = ssh2

const FIXTURES = path.join(import.meta.dirname, 'fixtures')
const KEY_NO_PASS = fs.readFileSync(path.join(FIXTURES, 'id_ed25519'))
const KEY_NO_PASS_PUB = fs.readFileSync(path.join(FIXTURES, 'id_ed25519.pub'))
const KEY_WITH_PASS = fs.readFileSync(path.join(FIXTURES, 'id_ed25519_pass'))
const KEY_WITH_PASS_PUB = fs.readFileSync(path.join(FIXTURES, 'id_ed25519_pass.pub'))
const KEY_PASSPHRASE = 'key-secret'

const tempDirs = []

function makeTempDir(prefix = 'rb-mock-selftest-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix))
  tempDirs.push(dir)
  return dir
}

function cleanupTempDirs() {
  for (const dir of tempDirs.splice(0)) {
    try {
      fs.rmSync(dir, { recursive: true, force: true })
    } catch {
      /* ignore */
    }
  }
}

function connect(mock, overrides = {}) {
  const client = new Client()
  const config = {
    host: '127.0.0.1',
    port: mock.port,
    username: MOCK_USERNAME,
    password: MOCK_PASSWORD,
    readyTimeout: 5000,
    ...overrides,
  }
  return new Promise((resolve, reject) => {
    let hostKeyBlob
    const previousVerifier = config.hostVerifier
    config.hostVerifier = (key, callback) => {
      const blob = Buffer.from(key)
      hostKeyBlob = blob
      if (typeof previousVerifier === 'function') {
        const result = previousVerifier(blob)
        if (result === false) return callback ? callback(false) : false
      }
      if (callback) return callback(true)
      return true
    }
    client.once('ready', () => {
      client.hostKeyBlob = hostKeyBlob
      resolve(client)
    })
    client.once('error', reject)
    client.connect(config)
  })
}

const endedClients = new WeakSet()

function endClient(client) {
  if (!client || endedClients.has(client)) return Promise.resolve()
  endedClients.add(client)
  return new Promise((resolve) => {
    let done = false
    const finish = () => {
      if (done) return
      done = true
      clearTimeout(timer)
      resolve()
    }
    const timer = setTimeout(finish, 1000)
    timer.unref?.()
    client.once('close', finish)
    client.once('error', finish)
    try {
      client.end()
    } catch {
      finish()
    }
  })
}

function execCapture(client, command, { stdin } = {}) {
  return new Promise((resolve, reject) => {
    client.exec(command, (error, stream) => {
      if (error) return reject(error)
      const stdout = []
      const stderr = []
      let code = null
      let signal = null
      stream.on('data', (data) => stdout.push(Buffer.from(data)))
      stream.stderr.on('data', (data) => stderr.push(Buffer.from(data)))
      stream.on('exit', (exitCode, exitSignal) => {
        code = exitCode
        signal = exitSignal
      })
      stream.on('close', () => {
        resolve({
          code,
          signal,
          stdout: Buffer.concat(stdout).toString('utf8'),
          stderr: Buffer.concat(stderr).toString('utf8'),
        })
      })
      stream.on('error', reject)
      if (stdin !== undefined) stream.write(stdin)
      stream.end()
    })
  })
}

function sftp(client) {
  return new Promise((resolve, reject) => {
    client.sftp((error, session) => (error ? reject(error) : resolve(session)))
  })
}

function sftpCall(session, method, ...args) {
  return new Promise((resolve, reject) => {
    session[method](...args, (error, value) => {
      if (error) {
        error.message = `sftp.${method}(${args.map((arg) => JSON.stringify(arg)).join(', ')}): ${error.message}`
        reject(error)
      } else {
        resolve(value)
      }
    })
  })
}

function shellOpen(client) {
  return new Promise((resolve, reject) => {
    client.shell(false, (error, stream) => {
      if (error) return reject(error)
      const state = { stream, output: '' }
      stream.on('data', (data) => {
        state.output += data.toString('utf8')
      })
      stream.stderr.on('data', (data) => {
        state.output += data.toString('utf8')
      })
      resolve(state)
    })
  })
}

/** Write to the persistent shell and wait until `needle` shows up in the output. */
function shellWaitFor(shell, input, needle, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup()
      reject(new Error(`Timed out waiting for ${JSON.stringify(needle)}; output=${JSON.stringify(shell.output)}`))
    }, timeoutMs)
    const onData = () => {
      if (shell.output.includes(needle)) {
        cleanup()
        resolve(shell.output)
      }
    }
    function cleanup() {
      clearTimeout(timer)
      shell.stream.removeListener('data', onData)
    }
    shell.stream.on('data', onData)
    shell.stream.write(input)
  })
}

const results = []

async function test(name, fn) {
  try {
    await fn()
    results.push({ name, ok: true })
    console.log(`ok - ${name}`)
  } catch (error) {
    results.push({ name, ok: false, error })
    console.error(`FAIL - ${name}`)
    console.error(error)
  }
}

async function main() {
  const dataDir = makeTempDir()
  const mock = createMockServer({
    dataDir,
    authorizedKeys: [KEY_NO_PASS_PUB, KEY_WITH_PASS_PUB],
  })

  try {
    await mock.listen()
  } catch (error) {
    console.error('mock server failed to listen:', error)
    throw error
  }

  try {
    await test('listens on 127.0.0.1 with an ephemeral port', () => {
      assert.ok(Number.isInteger(mock.port) && mock.port > 0)
      assert.equal(mock.listening, true)
      assert.match(mock.fingerprint, /^SHA256:[A-Za-z0-9+/]{43}$/)
    })

    await test('fingerprint matches ssh-keygen -lf', () => {
      const pubFile = path.join(makeTempDir(), 'host.pub')
      const publicKey = Buffer.isBuffer(mock.publicKey)
        ? `ssh-ed25519 ${mock.publicKey.toString('base64')} mock\n`
        : `${String(mock.publicKey).trim()}\n`
      fs.writeFileSync(pubFile, publicKey)
      const out = execFileSync('ssh-keygen', ['-lf', pubFile], { encoding: 'utf8' })
      const found = out.match(/SHA256:[A-Za-z0-9+/]+/)
      assert.ok(found, `ssh-keygen output: ${out}`)
      assert.equal(found[0], mock.fingerprint)
      assert.equal(mock.keyType, 'ssh-ed25519')
    })

    await test('password auth + exec + stable HOME + connection cwd', async () => {
      const client = await connect(mock)
      try {
        const home = await execCapture(client, 'printf %s "$HOME"')
        assert.equal(home.stdout, mock.homeDir)
        assert.equal(home.code, 0)

        const cwd = await execCapture(client, 'pwd')
        const workRootReal = fs.realpathSync.native(path.join(dataDir, 'work'))
        assert.ok(cwd.stdout.trim().startsWith(workRootReal), `cwd=${cwd.stdout}`)

        const version = await execCapture(client, 'bash --version | head -1')
        assert.match(version.stdout, /GNU bash/)
      } finally {
        await endClient(client)
      }
    })

    await test('exec reports stdout/stderr/exit code', async () => {
      const client = await connect(mock)
      try {
        const ok = await execCapture(client, 'echo out; echo err >&2')
        assert.equal(ok.stdout, 'out\n')
        assert.equal(ok.stderr, 'err\n')
        assert.equal(ok.code, 0)

        const failed = await execCapture(client, 'exit 7')
        assert.equal(failed.code, 7)

        const streams = await execCapture(client, 'echo stderr-line >&2; exit 2')
        assert.equal(streams.code, 2)
        assert.equal(streams.stderr, 'stderr-line\n')
      } finally {
        await endClient(client)
      }
    })

    await test('exec pipes stdin to the command', async () => {
      const client = await connect(mock)
      try {
        const result = await execCapture(client, 'cat', { stdin: 'hello-stdin\n' })
        assert.equal(result.stdout, 'hello-stdin\n')
        assert.equal(result.code, 0)
      } finally {
        await endClient(client)
      }
    })

    await test('sudo shim accepts the right password and rejects a wrong one', async () => {
      const client = await connect(mock)
      try {
        const good = await execCapture(client, "sudo -S -p '' -- bash -lc 'echo sudo-ok'", {
          stdin: `${MOCK_SUDO_PASSWORD}\n`,
        })
        assert.equal(good.code, 0, `stderr=${good.stderr}`)
        assert.equal(good.stdout, 'sudo-ok\n')
        assert.equal(good.stderr, '')

        const bad = await execCapture(client, "sudo -S -p '' -- bash -lc 'echo should-not-run'", {
          stdin: 'wrong-password\n',
        })
        assert.equal(bad.code, 1)
        assert.match(bad.stderr, /sudo: a password is required/)
        assert.equal(bad.stdout, '')
      } finally {
        await endClient(client)
      }
    })

    await test('shell keeps cd and exported variables across commands', async () => {
      const client = await connect(mock)
      try {
        const shell = await shellOpen(client)
        await shellWaitFor(
          shell,
          'mkdir -p "$HOME/persist" && cd "$HOME/persist" && echo __CD__$(pwd)\n',
          '__CD__',
        )
        assert.match(shell.output, new RegExp(`__CD__${mock.homeDir}/persist`))
        await shellWaitFor(shell, 'export RB_SELFTEST=42 && echo __EXPORT__$RB_SELFTEST\n', '__EXPORT__42')
        await shellWaitFor(shell, 'echo __PWD__$(pwd)__$RB_SELFTEST\n', `__PWD__${mock.homeDir}/persist__42`)
      } finally {
        await endClient(client)
      }
    })

    await test('sftp upload/download, stat, mkdir, rename, readdir, remove', async () => {
      const client = await connect(mock)
      const localDir = makeTempDir()
      try {
        const session = await sftp(client)
        const source = path.join(localDir, 'source.txt')
        const payload = 'remote-bash sftp payload\n'.repeat(100)
        fs.writeFileSync(source, payload)

        await sftpCall(session, 'fastPut', source, 'uploaded.txt')
        const stat = await sftpCall(session, 'stat', 'uploaded.txt')
        assert.equal(stat.size, Buffer.byteLength(payload))
        assert.equal(stat.isFile(), true)

        // exec sees the same HOME as sftp, so the uploaded file is there too.
        const seenByExec = await execCapture(client, 'cat "$HOME/uploaded.txt"')
        assert.equal(seenByExec.stdout, payload)

        const downloaddir = path.join(localDir, 'down')
        fs.mkdirSync(downloaddir)
        const target = path.join(downloaddir, 'downloaded.txt')
        await sftpCall(session, 'fastGet', 'uploaded.txt', target)
        assert.equal(fs.readFileSync(target, 'utf8'), payload)

        await sftpCall(session, 'mkdir', 'subdir')
        await sftpCall(session, 'rename', 'uploaded.txt', 'subdir/moved.txt')
        const movedStat = await sftpCall(session, 'stat', 'subdir/moved.txt')
        assert.equal(movedStat.size, Buffer.byteLength(payload))

        const entries = (await sftpCall(session, 'readdir', 'subdir')).map((entry) => entry.filename)
        assert.ok(entries.includes('moved.txt'), `entries=${entries}`)

        const realpath = await sftpCall(session, 'realpath', 'subdir')
        assert.equal(path.resolve(realpath), fs.realpathSync.native(path.join(mock.homeDir, 'subdir')))

        await sftpCall(session, 'unlink', 'subdir/moved.txt')
        await sftpCall(session, 'rmdir', 'subdir')
        await assert.rejects(sftpCall(session, 'stat', 'subdir/moved.txt'))
      } finally {
        await endClient(client)
      }
    })

    await test('sftp accepts absolute paths that use the unresolved tmpdir prefix', async () => {
      const client = await connect(mock)
      try {
        const session = await sftp(client)
        const absolute = path.join(mock.homeDir, 'absolute.txt')
        // homeDir is not necessarily a realpath (e.g. /var vs /private/var on
        // macOS); the server must normalise it before its containment check.
        const source = path.join(makeTempDir(), 'absolute-source.txt')
        fs.writeFileSync(source, 'absolute-path-ok')
        await sftpCall(session, 'fastPut', source, absolute)
        const result = await execCapture(client, 'cat "$HOME/absolute.txt"')
        assert.equal(result.stdout, 'absolute-path-ok')
        const real = await sftpCall(session, 'realpath', absolute)
        assert.equal(fs.readFileSync(real, 'utf8'), 'absolute-path-ok')
      } finally {
        await endClient(client)
      }
    })

    await test('publickey auth accepts both fixture keys (incl. passphrase key)', async () => {
      const plain = await connect(mock, { password: undefined, privateKey: KEY_NO_PASS })
      await endClient(plain)

      const encrypted = await connect(mock, {
        password: undefined,
        privateKey: KEY_WITH_PASS,
        passphrase: KEY_PASSPHRASE,
      })
      await endClient(encrypted)
    })

    await test('wrong password and unauthorized public key are rejected', async () => {
      await assert.rejects(connect(mock, { password: 'nope' }))
      const stranger = ssh2.utils.generateKeyPairSync('ed25519')
      await assert.rejects(connect(mock, { password: undefined, privateKey: stranger.private }))
    })

    await test('host key hot swap keeps the port and changes the fingerprint', async () => {
      const firstClient = await connect(mock)
      const firstFingerprint = mock.fingerprint
      assert.equal(fingerprintOf(firstClient.hostKeyBlob), firstFingerprint)
      await endClient(firstClient)

      const portBefore = mock.port
      await mock.setHostKey(mock.generateHostKey())
      assert.equal(mock.port, portBefore)
      assert.notEqual(mock.fingerprint, firstFingerprint)

      const secondClient = await connect(mock)
      try {
        assert.equal(fingerprintOf(secondClient.hostKeyBlob), mock.fingerprint)
        const result = await execCapture(secondClient, 'echo still-alive')
        assert.equal(result.stdout, 'still-alive\n')
      } finally {
        await endClient(secondClient)
      }
    })

    await test('close() stops listening', async () => {
      const port = mock.port
      await mock.close()
      await assert.rejects(connect(mock, { port }))
    })
  } finally {
    await mock.close().catch(() => {})
    cleanupTempDirs()
  }

  const failed = results.filter((result) => !result.ok)
  console.log(`\n${results.length - failed.length}/${results.length} mock-ssh-server self-tests passed`)
  process.exit(failed.length > 0 ? 1 : 0)
}

main().catch((error) => {
  console.error(error)
  cleanupTempDirs()
  process.exit(1)
})
