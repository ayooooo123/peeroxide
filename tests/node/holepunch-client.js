'use strict'

// A firewalled JS client on a local testnet: it can only reach `hash(pk)`
// servers through the testnet's relay nodes, so the connection is
// holepunched. Used to drive a firewalled peeroxide server (passive punch).

const DHT = require('hyperdht')
const createTestnet = require('hyperdht/testnet')
const readline = require('readline')

async function main () {
  const testnet = await createTestnet(3)
  const dht = testnet.createNode({ firewalled: true })
  await dht.fullyBootstrapped()
  console.log(JSON.stringify({
    port: testnet.bootstrap[0].port,
    publicKey: dht.defaultKeyPair.publicKey.toString('hex')
  }))
  const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity })
  lines.on('line', line => {
    const conn = dht.connect(Buffer.from(line, 'hex'))
    conn.on('error', err => { console.error(err); process.exitCode = 1 })
    conn.on('open', () => conn.write(Buffer.from('js-client')))
    conn.on('data', data => console.log(JSON.stringify({ data: data.toString() })))
  })
  lines.on('close', async () => { await testnet.destroy() })
}

main().catch(err => { console.error(err); process.exitCode = 1 })
