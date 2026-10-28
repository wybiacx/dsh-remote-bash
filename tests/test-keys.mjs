/** Test-only Ed25519 key generation with lossless OpenSSH serialization. */
import { generateKeyPairSync, randomBytes } from 'node:crypto'

function uint32(value) {
  const result = Buffer.alloc(4)
  result.writeUInt32BE(value)
  return result
}

function sshString(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value)
  return Buffer.concat([uint32(bytes.length), bytes])
}

/**
 * ssh2 1.17's generator strips all leading zeros from the DER BIT STRING,
 * including valid public-key bytes. Ed25519 keys are fixed-width byte strings,
 * not integers. Export via Node's JWK so all 32 bytes survive serialization.
 * An optional native private KeyObject allows deterministic boundary fixtures.
 */
export function generateEd25519KeyPair(privateKey = generateKeyPairSync('ed25519').privateKey) {
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('Expected a native Ed25519 private KeyObject')
  }
  const jwk = privateKey.export({ format: 'jwk' })
  const publicBytes = Buffer.from(jwk.x, 'base64url')
  const seed = Buffer.from(jwk.d, 'base64url')
  if (publicBytes.length !== 32 || seed.length !== 32) throw new Error('Invalid Ed25519 key width')

  const keyType = 'ssh-ed25519'
  const publicBlob = Buffer.concat([sshString(keyType), sshString(publicBytes)])
  const check = randomBytes(4)
  const body = Buffer.concat([
    check, check, sshString(keyType), sshString(publicBytes),
    sshString(Buffer.concat([seed, publicBytes])), sshString('remote-bash test fixture'),
  ])
  const padding = Buffer.from(Array.from({ length: (8 - body.length % 8) % 8 }, (_, i) => i + 1))
  const envelope = Buffer.concat([
    Buffer.from('openssh-key-v1\0'), sshString('none'), sshString('none'), sshString(''),
    uint32(1), sshString(publicBlob), sshString(Buffer.concat([body, padding])),
  ])
  const lines = envelope.toString('base64').match(/.{1,64}/g).join('\n')
  return {
    private: `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines}\n-----END OPENSSH PRIVATE KEY-----\n`,
    public: `${keyType} ${publicBlob.toString('base64')}`,
  }
}
