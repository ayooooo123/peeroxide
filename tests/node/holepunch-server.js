'use strict'

// A firewalled JS server on a local testnet: a peeroxide client must reach it
// through the testnet's relays and holepunch. Used to drive the Rust
// initiator side of the punch.

const DHT = require('hyperdht')
const createTestnet = require('hyperdht/testnet')
const readline = require('readline')

async function main () {
  const testnet = await createTestnet(3)
  const dht = testnet.createNode({ firewalled: true })
  await dht.fullyBootstrapped()
  const keyPair = DHT.keyPair()
  const server = dht.createServer(conn => {
    conn.on('error', err => console.error(err))
    conn.on('data', data => conn.write(data))
  })
  await server.listen(keyPair)
  console.log(JSON.stringify({
    port: testnet.bootstrap[0].port,
    publicKey: keyPair.publicKey.toString('hex')
  }))
  const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
  lines.on('close', async () => { await testnet.destroy() })
}

main().catch(err => { console.error(err); process.exitCode = 1 })
