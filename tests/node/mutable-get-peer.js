'use strict'

// A JS testnet that reads back mutable records a peeroxide node stored.
// stdout: {"port"}; then, per stdin line "<publicKeyHex> <seq>", the result
// of `dht.mutableGet(publicKey, { seq })`.

const createTestnet = require('hyperdht/testnet')
const b4a = require('b4a')
const readline = require('readline')

async function main () {
  const testnet = await createTestnet(3)
  const node = testnet.createNode({ firewalled: false })
  await node.fullyBootstrapped()

  console.log(JSON.stringify({ port: testnet.bootstrap[0].port }))

  const rl = readline.createInterface({ input: process.stdin })
  for await (const line of rl) {
    const [hex, seq] = line.trim().split(' ')
    const res = await node.mutableGet(b4a.from(hex, 'hex'), { seq: Number(seq), latest: false })
    console.log(JSON.stringify(res
      ? { seq: res.seq, value: b4a.toString(res.value), signature: b4a.toString(res.signature, 'hex') }
      : { missing: true }))
  }
  await testnet.destroy()
}

main().catch(err => { console.error(err); process.exitCode = 1 })
